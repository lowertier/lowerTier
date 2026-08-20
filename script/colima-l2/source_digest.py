#!/usr/bin/env python3

import hashlib
import os
import pathlib
import subprocess
import sys


def source_digest(root: pathlib.Path) -> str:
    paths = subprocess.check_output(
        [
            "git",
            "-C",
            str(root),
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ]
    ).split(b"\0")
    digest = hashlib.sha256()
    for raw_path in sorted(path for path in paths if path):
        path = root / os.fsdecode(raw_path)
        digest.update(raw_path)
        digest.update(b"\0")
        if path.is_symlink():
            digest.update(b"link\0")
            digest.update(os.fsencode(os.readlink(path)))
        else:
            digest.update(b"file\0")
            digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: source_digest.py REPOSITORY")
    print(source_digest(pathlib.Path(sys.argv[1]).resolve()))


if __name__ == "__main__":
    main()
