use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use anyhow::Context;
use rand::RngCore;

pub struct ControlToken(Vec<u8>);

impl ControlToken {
    pub fn load_or_create(path: &Path) -> anyhow::Result<Self> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let (mut file, created) = match options.open(path) {
            Ok(file) => (file, true),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (
                File::open(path).context("Cannot open the control token file.")?,
                false,
            ),
            Err(error) => return Err(error).context("Cannot create the control token file."),
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
            anyhow::ensure!(
                !std::fs::symlink_metadata(path)?.file_type().is_symlink(),
                "The control token file cannot be a symbolic link."
            );
        }
        #[cfg(windows)]
        secure_windows_token(path, created)?;
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
fn secure_windows_token(path: &Path, created: bool) -> anyhow::Result<()> {
    let script = r#"
$ErrorActionPreference = 'Stop'
$path = $env:LOWTIER_TOKEN_ACL_PATH
$owner = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
if ($env:LOWTIER_TOKEN_ACL_CREATE -eq '1') {
    $acl = New-Object System.Security.AccessControl.FileSecurity
    $acl.SetOwner($owner)
    $acl.SetAccessRuleProtection($true, $false)
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($owner, 'FullControl', 'Allow')
    $acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $path -AclObject $acl
}
$acl = Get-Acl -LiteralPath $path
if ($acl.GetOwner([System.Security.Principal.SecurityIdentifier]) -ne $owner) { exit 1 }
if (-not $acl.AreAccessRulesProtected) { exit 1 }
foreach ($rule in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
    if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference -ne $owner) { exit 1 }
}
"#;
    let status = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .env("LOWTIER_TOKEN_ACL_PATH", path)
        .env("LOWTIER_TOKEN_ACL_CREATE", if created { "1" } else { "0" })
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .context("Cannot verify the control token owner ACL.")?;
    anyhow::ensure!(
        status.success(),
        "The control token requires an owner-only ACL."
    );
    Ok(())
}
