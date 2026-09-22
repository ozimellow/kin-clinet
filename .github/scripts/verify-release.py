"""Generic verification of signed, reviewed release archives."""
import hashlib
import json
import re
import stat
import subprocess
import sys
import zipfile
from pathlib import Path

KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO4x6/iMFbf8rOg0xgk2Hh9OiKgtcxm8yos6gFWE8CvM"
MAX = 512 * 1024 * 1024

def require(ok, message):
    if not ok:
        raise ValueError(message)

def digest(data):
    return hashlib.sha256(data).hexdigest()

def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "Duplicate metadata key")
        result[key] = value
    return result

def parse(data):
    return json.loads(data, object_pairs_hook=unique_object)

def safe_path(value):
    return isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", value) and all(p not in (".", "..") for p in value.split("/"))

def verify(manifest_path, directory):
    manifest = parse(Path(manifest_path).read_bytes())
    require(set(manifest) == {"schemaVersion", "tag", "manualAcceptance", "assets", "reviewedPackageSha256", "reviewedNotesSha256"}, "Unreviewed release metadata")
    require(manifest["schemaVersion"] == 1 and manifest["manualAcceptance"] is True, "Exact candidate acceptance is required")
    require(re.fullmatch(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", manifest["tag"]), "Invalid release tag")
    assets = manifest["assets"]
    archives = [name for name in assets if safe_path(name) and "/" not in name and name.endswith(".zip")]
    require(len(archives) == 1, "Exactly one reviewed archive is required")
    name = archives[0]
    require(set(assets) == {name, "SHA256SUMS", "SHA256SUMS.sig", "release-signing-key.pub", "allowed_signers"}, "Unexpected release assets")
    require(all(re.fullmatch(r"[a-f0-9]{64}", str(value)) for value in assets.values()), "Invalid asset digest")
    require(manifest["reviewedPackageSha256"] == assets[name], "Exact package content review is required")
    require(assets[name] != "a78fb1794fd4f80adc5f54534240f8de1f9fd3cfc18b711cc3af86047e1e7ff1", "Withdrawn package")
    require(digest(Path(manifest_path).with_name("release.md").read_bytes()) == manifest["reviewedNotesSha256"], "Exact release notes review is required")
    directory = Path(directory)
    require(not directory.is_symlink() and {p.name for p in directory.iterdir()} == set(assets), "Unexpected asset directory")
    for asset, expected in assets.items():
        p = directory / asset
        require(p.is_file() and not p.is_symlink() and p.stat().st_size <= MAX, "Invalid release asset")
        require(digest(p.read_bytes()) == expected, "Release asset digest mismatch")
    require((directory / "release-signing-key.pub").read_text().strip() == KEY, "Unexpected release key")
    require((directory / "allowed_signers").read_text().strip() == 'publisher namespaces="release" ' + KEY, "Unexpected signer")
    checksums = (assets[name] + "  " + name + "\n").encode()
    require((directory / "SHA256SUMS").read_bytes() == checksums, "Unexpected checksum statement")
    signature = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", str(directory / "allowed_signers"), "-I", "publisher", "-n", "release", "-s", str(directory / "SHA256SUMS.sig")], input=checksums, capture_output=True, timeout=20)
    require(signature.returncode == 0, "Release signature failed")
    prefix = name[:-4] + "/"
    with zipfile.ZipFile(directory / name) as archive:
        entries = archive.infolist()
        require(not archive.comment, "Archive comments are forbidden")
        require(1 < len(entries) <= 64 and sum(i.file_size for i in entries) < MAX, "Invalid archive size")
        require(len({i.filename.casefold() for i in entries}) == len(entries), "Duplicate archive entry")
        for item in entries:
            require(not item.comment and not item.extra, "Unreviewed archive metadata")
            require(item.filename.startswith(prefix) and safe_path(item.filename[len(prefix):]), "Unexpected archive path")
            require(not item.is_dir() and not stat.S_ISLNK(item.external_attr >> 16) and not item.flag_bits & 1, "Unsupported archive entry")
        data = {i.filename[len(prefix):]: archive.read(i) for i in entries}
    inventory_name = "application-manifest.json"
    require(inventory_name in data, "Package inventory is required")
    binaries = {p for p in data if p.endswith((".exe", ".dll"))}
    root_apps = {p for p in binaries if "/" not in p and p.endswith(".exe")}
    require(len(root_apps) == 1, "One application is required")
    require(all(p in root_apps or p.startswith("resources/") for p in binaries), "Unexpected binary placement")
    metadata = {p for p in data if p.startswith("resources/") and p.endswith("/manifest.json")}
    require(set(data) == binaries | metadata | {inventory_name}, "Loose documents or unreviewed resources are forbidden")
    inventory = parse(data[inventory_name])
    require(set(inventory) == {"schemaVersion", "files"} and inventory["schemaVersion"] == 2, "Unknown package metadata")
    rows = inventory["files"]
    require(all(set(row) == {"path", "sha256"} for row in rows), "Unknown file metadata")
    hashes = {row["path"]: row["sha256"] for row in rows}
    require(len(hashes) == len(rows) and set(hashes) == set(data) - {inventory_name}, "Package inventory mismatch")
    for p, expected in hashes.items():
        require(digest(data[p]) == expected, "Package file digest mismatch")
    for p in binaries:
        require(data[p][:2] == b"MZ", "Expected a compiled application resource")
    for p in metadata:
        info = parse(data[p])
        require(set(info) == {"product", "version", "files"}, "Unknown resource metadata")
        require(re.fullmatch(r"[a-zA-Z0-9_.-]{1,64}", info["product"]) and info["version"] == manifest["tag"][1:], "Invalid resource identity")
        rows = info["files"]
        require(all(set(row) == {"path", "sha256"} and safe_path(row["path"]) for row in rows), "Unknown resource file metadata")
        paths = [p.rsplit("/", 1)[0] + "/" + row["path"] for row in rows]
        require(len(set(paths)) == len(paths) and all(q in binaries for q in paths), "Invalid resource inventory")
        for row, q in zip(rows, paths):
            require(digest(data[q]) == row["sha256"], "Resource digest mismatch")
    print("PASS: reviewed release archive and signature verified")

if __name__ == "__main__":
    try:
        require(len(sys.argv) == 3, "Usage: verify-release.py MANIFEST ASSET_DIRECTORY")
        verify(sys.argv[1], sys.argv[2])
    except Exception:
        print("Release verification failed", file=sys.stderr)
        sys.exit(1)
