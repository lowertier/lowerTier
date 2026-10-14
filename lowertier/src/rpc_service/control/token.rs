use std::{
    fs::OpenOptions,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use anyhow::Context;
use rand::RngCore;

pub struct ControlToken(Vec<u8>);

impl ControlToken {
    pub fn load_or_create(path: &Path) -> anyhow::Result<Self> {
        #[cfg(not(windows))]
        let (mut file, created) = Self::open_token_file(path)?;
        #[cfg(windows)]
        let (mut file, created) = {
            use std::os::windows::fs::OpenOptionsExt;
            let created = create_windows_token(path)?;
            let mut options = OpenOptions::new();
            // Block path replacement while the ACL check uses the file path.
            options.read(true).write(created).share_mode(0);
            let file = options
                .open(path)
                .context("Cannot open the control token file.")?;
            secure_windows_token(path)?;
            (file, created)
        };
        let metadata = file.metadata()?;
        anyhow::ensure!(
            metadata.is_file(),
            "The control token must be a regular file."
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            anyhow::ensure!(
                metadata.mode() & 0o777 == 0o600
                    && metadata.uid() == unsafe { nix::libc::geteuid() }
                    && metadata.nlink() == 1,
                "The control token file requires mode 0600 and the current owner."
            );
        }
        anyhow::ensure!(
            !std::fs::symlink_metadata(path)?.file_type().is_symlink(),
            "The control token file cannot be a symbolic link."
        );
        if created {
            let mut bytes = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut bytes);
            use base64::Engine;
            let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
            file.write_all(token.as_bytes())?;
            file.write_all(b"\n")?;
            file.sync_all()?;
            return Ok(Self(token.into_bytes()));
        }
        anyhow::ensure!(
            metadata.len() <= 4096,
            "The control token file is too large."
        );
        let mut token = String::new();
        file.take(4097).read_to_string(&mut token)?;
        let token = token.trim();
        anyhow::ensure!(
            token.len() >= 32 && !token.chars().any(char::is_whitespace),
            "The control token must contain at least 32 characters without whitespace."
        );
        Ok(Self(token.as_bytes().to_vec()))
    }

    #[cfg(not(windows))]
    fn open_token_file(path: &Path) -> anyhow::Result<(std::fs::File, bool)> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(nix::libc::O_NOFOLLOW);
        }
        match options.open(path) {
            Ok(file) => Ok((file, true)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let mut existing = OpenOptions::new();
                existing.read(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    existing.custom_flags(nix::libc::O_NOFOLLOW);
                }
                Ok((
                    existing
                        .open(path)
                        .context("Cannot open the control token file.")?,
                    false,
                ))
            }
            Err(error) => Err(error).context("Cannot create the control token file."),
        }
    }

    pub fn matches(&self, supplied: &str) -> bool {
        crate::common::verify_slices_are_equal(&self.0, supplied.as_bytes()).is_ok()
    }

    pub fn default_path(config_dir: Option<&Path>) -> anyhow::Result<PathBuf> {
        if let Some(path) = std::env::var_os("LOWTIER_CONTROL_TOKEN_FILE") {
            return Ok(path.into());
        }
        if let Some(dir) = config_dir {
            return Ok(dir.join("control.token"));
        }
        let directory = PathBuf::from(
            std::env::var_os(if cfg!(windows) {
                "LOCALAPPDATA"
            } else {
                "HOME"
            })
            .context("Cannot find the control token directory.")?,
        )
        .join(if cfg!(windows) {
            "LowTier"
        } else {
            ".config/lowertier"
        });
        std::fs::create_dir_all(&directory)?;
        Ok(directory.join("control.token"))
    }
}

#[cfg(windows)]
pub(super) fn create_windows_token(path: &Path) -> anyhow::Result<bool> {
    let script = r#"
$ErrorActionPreference = 'Stop'
$path = $env:LOWTIER_TOKEN_ACL_PATH
$owner = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$acl = New-Object System.Security.AccessControl.FileSecurity
$acl.SetOwner($owner)
$acl.SetAccessRuleProtection($true, $false)
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule($owner, 'FullControl', 'Allow')
$acl.AddAccessRule($rule)
try {
    $rights = [System.Security.AccessControl.FileSystemRights]::Read -bor [System.Security.AccessControl.FileSystemRights]::Write
    $stream = New-Object System.IO.FileStream -ArgumentList @($path, [System.IO.FileMode]::CreateNew, $rights, [System.IO.FileShare]::None, 4096, [System.IO.FileOptions]::WriteThrough, $acl)
    $stream.Dispose()
} catch {
    $code = $_.Exception.GetBaseException().HResult -band 0xffff
    if ($code -eq 80 -or $code -eq 183) { exit 2 }
    exit 1
}
"#;
    // The FileStream constructor applies the owner ACL during file creation.
    match windows_token_command(path, script)?.code() {
        Some(0) => Ok(true),
        Some(2) => Ok(false),
        _ => anyhow::bail!("Cannot create the control token with an owner-only ACL."),
    }
}

#[cfg(windows)]
pub(super) fn secure_windows_token(path: &Path) -> anyhow::Result<()> {
    let script = r#"
$ErrorActionPreference = 'Stop'
$path = $env:LOWTIER_TOKEN_ACL_PATH
$owner = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$acl = Get-Acl -LiteralPath $path
if ($acl.GetOwner([System.Security.Principal.SecurityIdentifier]) -ne $owner) { exit 1 }
if (-not $acl.AreAccessRulesProtected) { exit 1 }
foreach ($rule in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
    if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference -ne $owner) { exit 1 }
}
"#;
    anyhow::ensure!(
        windows_token_command(path, script)?.success(),
        "The control token requires an owner-only ACL."
    );
    Ok(())
}

#[cfg(windows)]
fn windows_token_command(path: &Path, script: &str) -> anyhow::Result<std::process::ExitStatus> {
    std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .env("LOWTIER_TOKEN_ACL_PATH", path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .context("Cannot verify the control token owner ACL.")
}
