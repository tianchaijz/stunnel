#!/usr/bin/env python3
"""Package host binaries and the config generator in a stunnel/ folder.

Run from any directory: python3 /path/to/stunnel/scripts/release.py
Requires Cargo, rustc, and Python 3.10+. Does not commit, tag, or publish.
"""

import hashlib
import json
import os
import shutil
import subprocess
import tarfile
from pathlib import Path

if not all(shutil.which(tool) for tool in ("cargo", "rustc")):
    cargo_bin = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo")) / "bin"
    os.environ["PATH"] = os.environ.get("PATH", "") + os.pathsep + str(cargo_bin)
missing = [tool for tool in ("cargo", "rustc") if not shutil.which(tool)]
if missing:
    raise SystemExit(
        f"Missing Rust tools: {', '.join(missing)}. "
        "Install Rust or add its bin directory to PATH."
    )

root = Path(__file__).resolve().parents[1]
metadata = json.loads(
    subprocess.check_output(
        ["cargo", "metadata", "--locked", "--no-deps", "--format-version=1"],
        cwd=root,
    )
)
package = next(item for item in metadata["packages"] if item["name"] == "stunnel")
host = next(
    line.removeprefix("host: ")
    for line in subprocess.check_output(
        ["rustc", "-vV"],
        text=True,
    ).splitlines()
    if line.startswith("host: ")
)
subprocess.run(
    ["cargo", "build", "--release", "--locked", "--bins", "--target", host],
    cwd=root,
    check=True,
)

target = Path(metadata["target_directory"])
output = target / "releases"
output.mkdir(parents=True, exist_ok=True)
name = f"stunnel-v{package['version']}-{host}"
archive = output / f"{name}.tar.gz"
suffix = ".exe" if "windows" in host else ""
with tarfile.open(archive, "w:gz") as bundle:
    for binary in ("stunnel_client", "stunnel_server", "certgen"):
        filename = binary + suffix
        bundle.add(target / host / "release" / filename, arcname=f"stunnel/{filename}")
    bundle.add(
        root / "scripts/generate_configs.py", arcname="stunnel/generate_configs.py"
    )

checksum = output / f"{archive.name}.sha256"
checksum.write_text(
    f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n"
)
print(f"Archive: {archive}")
print(f"Checksum: {checksum}")
