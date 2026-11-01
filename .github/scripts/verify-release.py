"""Generic verification of signed, reviewed release archives."""
import hashlib
import http.client
import json
import os
import re
import stat
import struct
import tempfile
import subprocess
import sys
import zipfile
from pathlib import Path
from urllib.parse import quote

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

ANDROID_CERTIFICATE = "1b366e9e20fd45af9608d4b1e9b30ae709c6bcd87bd7cdaaf89c0bd5dc881823"

def android_tools():
    sdk = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    require(bool(sdk), "Android SDK is required")
    version = os.environ.get("ANDROID_BUILD_TOOLS_VERSION", "36.0.0")
    require(version in ("35.0.0", "36.0.0"), "Unsupported Android verification tools")
    directory = Path(sdk) / "build-tools" / version
    require(directory.is_dir(), "Android verification tools are missing")
    signer = directory / ("apksigner.bat" if os.name == "nt" else "apksigner")
    if signer.is_file():
        signing = [str(signer)]
    else:
        jar = directory / "lib/apksigner.jar"
        java_home = os.environ.get("JAVA_HOME")
        require(bool(java_home), "Java is required for APK verification")
        java = Path(java_home) / "bin" / ("java.exe" if os.name == "nt" else "java")
        require(jar.is_file() and java.is_file(), "APK verification tools are missing")
        signing = [str(java), "-jar", str(jar)]
    aapt = directory / ("aapt.exe" if os.name == "nt" else "aapt")
    if not aapt.is_file():
        aapt = directory / ("aapt2.exe" if os.name == "nt" else "aapt2")
    align = directory / ("zipalign.exe" if os.name == "nt" else "zipalign")
    require(aapt.is_file() and align.is_file(), "APK inspection tools are missing")
    return signing, str(aapt), str(align)

def verify_android(path, manifest):
    identity = manifest["android"]
    require(isinstance(identity, dict) and set(identity) == {"certificateSha256", "versionCode", "inventorySha256"}, "Unknown Android metadata")
    require(identity["certificateSha256"] == ANDROID_CERTIFICATE, "Unexpected Android publisher")
    require(type(identity["versionCode"]) is int and 0 < identity["versionCode"] <= 2100000000, "Invalid Android version code")
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        require(not archive.comment and 1 < len(entries) <= 10000 and sum(i.file_size for i in entries) < MAX, "Invalid APK size")
        require(len({i.filename.casefold() for i in entries}) == len(entries), "Duplicate APK entry")
        inventory = []
        for item in entries:
            require(safe_path(item.filename) and not item.is_dir() and not item.comment, "Invalid APK path")
            require(not stat.S_ISLNK(item.external_attr >> 16) and not item.flag_bits & 1, "Unsupported APK entry")
            require(not item.filename.lower().endswith((".java", ".kt", ".go", ".cs", ".map", ".pdb", ".jks", ".p12", ".pem")), "Unexpected source or signing material")
            inventory.append({"path": item.filename, "sha256": digest(archive.read(item))})
        require({"AndroidManifest.xml", "resources.arsc", "classes.dex"}.issubset({i.filename for i in entries}), "Incomplete Android package")
        inventory.sort(key=lambda row: row["path"])
        encoded = json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode()
        require(digest(encoded) == identity["inventorySha256"], "APK content review mismatch")
    signing, aapt, align = android_tools()
    result = subprocess.run(signing + ["verify", "--verbose", "--print-certs", str(path)], capture_output=True, text=True, timeout=60)
    require(result.returncode == 0, "APK signature failed")
    certificates = re.findall(r"Signer #\d+ certificate SHA-256 digest: ([a-f0-9]{64})", result.stdout)
    require(certificates == [ANDROID_CERTIFICATE], "Unexpected APK signer")
    require("Verified using v3 scheme (APK Signature Scheme v3): true" in result.stdout, "APK v3 signature required")
    result = subprocess.run([aapt, "dump", "badging", str(path)], capture_output=True, text=True, timeout=30, encoding="utf-8")
    require(result.returncode == 0, "APK identity could not be read")
    package = re.search(r"^package: name='([^']+)' versionCode='([^']+)' versionName='([^']+)'", result.stdout, re.M)
    require(package is not None and package.groups() == ("com.kin.client", str(identity["versionCode"]), manifest["tag"][1:]), "APK identity mismatch")
    require("application-debuggable" not in result.stdout, "Debug APK is forbidden")
    require(re.search(r"^native-code: 'arm64-v8a'\s*$", result.stdout, re.M) is not None, "Unexpected APK architecture")
    result = subprocess.run([align, "-c", "-P", "16", "4", str(path)], capture_output=True, timeout=30)
    require(result.returncode == 0, "APK alignment failed")

def verify_windows(path, name, manifest):
    prefix = name[:-4] + "/"
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        require(not archive.comment, "Archive comments are forbidden")
        require(1 < len(entries) <= 64 and sum(i.file_size for i in entries) < MAX, "Invalid archive size")
        require(len({i.filename.casefold() for i in entries}) == len(entries), "Duplicate archive entry")
        for item in entries:
            require(not item.comment and not item.extra, "Unreviewed archive metadata")
            require(item.orig_filename == item.filename and item.filename.startswith(prefix) and safe_path(item.filename[len(prefix):]), "Unexpected archive path")
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




def verify_elf(data):
    require(len(data) >= 64 and data[:6] == b"\x7fELF\x02\x01", "Expected a native 64-bit application resource")
    require(struct.unpack_from("<H", data, 16)[0] in (2, 3) and struct.unpack_from("<H", data, 18)[0] == 62, "Unexpected native architecture")
    offset = struct.unpack_from("<Q", data, 40)[0]
    size, count, strings = struct.unpack_from("<HHH", data, 58)
    require(size == 64 and 0 < strings < count < 65535 and 64 <= offset <= len(data) and offset + size * count <= len(data), "Invalid native section inventory")
    rows = [struct.unpack_from("<IIQQQQIIQQ", data, offset + size * i) for i in range(count)]
    names = rows[strings]
    require(names[1] == 3 and names[4] + names[5] <= len(data), "Invalid native section names")
    table = data[names[4]:names[4] + names[5]]
    for row in rows:
        require(row[0] < len(table) and table.find(b"\0", row[0]) >= 0, "Invalid native section name")
        name = table[row[0]:table.find(b"\0", row[0])]
        require(name != b".symtab" and not name.startswith((b".debug_", b".zdebug_")), "Unreviewed native symbols")
        require(row[1] == 8 or row[4] + row[5] <= len(data), "Invalid native section range")


def verify_linux(path, name, version):
    prefix = name[:-4] + "/"
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        require(not archive.comment and 1 < len(entries) <= 64 and sum(i.file_size for i in entries) < MAX, "Invalid native archive size")
        require(len({i.filename.casefold() for i in entries}) == len(entries), "Duplicate native archive entry")
        for item in entries:
            require(not item.comment and not item.extra and item.orig_filename == item.filename and item.filename.startswith(prefix) and safe_path(item.filename[len(prefix):]), "Unexpected native archive path")
            require(item.create_system == 3 and not item.is_dir() and stat.S_ISREG(item.external_attr >> 16) and not item.flag_bits & 1, "Unsupported native archive entry")
            require(stat.S_IMODE(item.external_attr >> 16) in (0o644, 0o755), "Unexpected native file permissions")
        data = {i.filename[len(prefix):]: archive.read(i) for i in entries}
        modes = {i.filename[len(prefix):]: stat.S_IMODE(i.external_attr >> 16) for i in entries}
    require("manifest.json" in data and len(data["manifest.json"]) <= 8192, "Native package inventory is required")
    inventory = parse(data["manifest.json"])
    require(set(inventory) == {"schemaVersion", "version", "platform", "architecture", "files"} and type(inventory["schemaVersion"]) is int and inventory["schemaVersion"] == 1, "Unknown native package metadata")
    require(inventory["version"] == version and inventory["platform"] == "linux" and inventory["architecture"] == "x64", "Native package identity mismatch")
    files = inventory["files"]
    require(isinstance(files, dict) and set(files) == set(data) - {"manifest.json"} and modes["manifest.json"] == 0o644, "Native package inventory mismatch")
    require(any(modes[n] == 0o755 for n in files), "Native application is required")
    for filename, expected in files.items():
        require(safe_path(filename) and isinstance(expected, str) and re.fullmatch(r"[a-f0-9]{64}", expected) and digest(data[filename]) == expected, "Native file digest mismatch")
        verify_elf(data[filename])


def verify_linux_assets(directory, version, assets):
    name = "kin-clinet-" + version + "-linux-x64.zip"
    sums_name = "SHA256SUMS-linux-x64"
    descriptor_name = "linux-x64.json"
    descriptor = parse((directory / descriptor_name).read_bytes())
    require(set(descriptor) == {"schemaVersion", "version", "platform", "architecture", "package"} and type(descriptor["schemaVersion"]) is int and descriptor["schemaVersion"] == 1, "Unknown extension descriptor")
    require(descriptor["version"] == version and descriptor["platform"] == "linux" and descriptor["architecture"] == "x64", "Extension descriptor identity mismatch")
    package = descriptor["package"]
    require(isinstance(package, dict) and set(package) == {"name", "sha256", "bytes"} and package["name"] == name and package["sha256"] == assets[name] and type(package["bytes"]) is int and package["bytes"] == (directory / name).stat().st_size, "Extension descriptor package mismatch")
    statement = (assets[name] + "  " + name + "\n").encode()
    require((directory / sums_name).read_bytes() == statement, "Unexpected extension checksum statement")
    with tempfile.TemporaryDirectory(prefix="release-integrity-") as temp:
        allowed = Path(temp) / "allowed_signers"
        allowed.write_text('publisher namespaces="release" ' + KEY + "\n", encoding="utf-8")
        signature = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", str(allowed), "-I", "publisher", "-n", "release", "-s", str(directory / (sums_name + ".sig"))], input=statement, capture_output=True, timeout=20)
        require(signature.returncode == 0, "Extension release signature failed")
    verify_linux(directory / name, name, version)


def verify_extension(manifest_path, directory):
    """Verify only the separately reviewed extension asset directory."""
    manifest_path = Path(manifest_path)
    manifest = parse(manifest_path.read_bytes())
    require(set(manifest) == {"schemaVersion", "tag", "tagCommit", "platform", "manualAcceptance", "assets", "reviewedPackageSha256", "reviewedNotesSha256"}, "Unknown platform extension metadata")
    require(type(manifest["schemaVersion"]) is int and manifest["schemaVersion"] == 1 and manifest["manualAcceptance"] is True, "Exact extension acceptance is required")
    require(re.fullmatch(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-dev\.[1-9][0-9]*)?", manifest["tag"]) and re.fullmatch(r"[a-f0-9]{40}", manifest["tagCommit"]) and manifest["platform"] == "linux-x64", "Invalid platform extension identity")
    version = manifest["tag"][1:]
    name = "kin-clinet-" + version + "-linux-x64.zip"
    sums_name = "SHA256SUMS-linux-x64"
    descriptor_name = "linux-x64.json"
    assets = manifest["assets"]
    require(isinstance(assets, dict) and set(assets) == {name, sums_name, sums_name + ".sig", descriptor_name}, "Unexpected extension assets")
    require(all(isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) for value in assets.values()) and manifest["reviewedPackageSha256"] == assets[name], "Exact extension package review is required")
    require(digest(manifest_path.with_name("release.md").read_bytes()) == manifest["reviewedNotesSha256"], "Exact extension notes review is required")
    directory = Path(directory)
    require(not directory.is_symlink() and {p.name for p in directory.iterdir()} == set(assets), "Unexpected extension asset directory")
    for filename, expected in assets.items():
        file = directory / filename
        require(file.is_file() and not file.is_symlink() and 0 < file.stat().st_size <= MAX and digest(file.read_bytes()) == expected, "Extension asset digest mismatch")
    require((directory / descriptor_name).stat().st_size <= 8192 and (directory / sums_name).stat().st_size <= 8192 and (directory / (sums_name + ".sig")).stat().st_size <= 2048, "Extension metadata exceeds limits")
    verify_linux_assets(directory, version, assets)
    print("PASS: reviewed platform extension verified; existing release assets are separate")


def verify(manifest_path, directory):
    manifest = parse(Path(manifest_path).read_bytes())
    multiplatform = manifest.get("schemaVersion") == 5
    recovery = manifest.get("schemaVersion") == 4
    bundle = manifest.get("schemaVersion") in (3, 4, 5)
    android = manifest.get("schemaVersion") in (2, 3, 4, 5)
    review_field = "reviewedPackages" if bundle else "reviewedPackageSha256"
    require(set(manifest) == ({"schemaVersion", "tag", "manualAcceptance", "assets", review_field, "reviewedNotesSha256"} | ({"android"} if android else set()) | ({"stableRecovery"} if recovery else set())), "Unreviewed release metadata")
    require(type(manifest["schemaVersion"]) is int and manifest["schemaVersion"] in (1, 2, 3, 4, 5) and manifest["manualAcceptance"] is True, "Exact candidate acceptance is required")
    require(re.fullmatch(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-dev\.[1-9][0-9]*)?", manifest["tag"]), "Invalid release tag")
    assets = manifest["assets"]
    require(isinstance(assets, dict), "Invalid assets")
    windows_name = "kin-clinet-" + manifest["tag"][1:] + "-windows-x64.zip"
    android_name = "kin-clinet-" + manifest["tag"][1:] + "-android-arm64.apk"
    names = [windows_name, android_name] if bundle else [android_name if android else windows_name]
    linux_name = "kin-clinet-" + manifest["tag"][1:] + "-linux-x64.zip"
    if multiplatform:
        names.append(linux_name)
    if recovery:
        entry = manifest["stableRecovery"]
        require(isinstance(entry, dict) and set(entry) == {"version", "android"}, "Unknown recovery metadata")
        require(re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", entry["version"]), "Recovery must be Stable")
        require("-dev." in manifest["tag"], "Recovery belongs to a preview release")
        require(tuple(map(int, entry["version"].split("."))) < tuple(map(int, manifest["tag"][1:].split("-")[0].split("."))), "Recovery must restore an earlier stable series")
        require(entry["android"]["versionCode"] == manifest["android"]["versionCode"], "Channel pair must share its installation generation")
        recovery_name = "kin-clinet-" + entry["version"] + "-android-arm64-recovery-" + str(entry["android"]["versionCode"]) + ".apk"
        names.append(recovery_name)
    name = names[0]
    extra = {"SHA256SUMS-linux-x64", "SHA256SUMS-linux-x64.sig", "linux-x64.json"} if multiplatform else set()
    require(set(assets) == set(names) | {"SHA256SUMS", "SHA256SUMS.sig", "release-signing-key.pub", "allowed_signers"} | extra, "Archive version mismatch or unexpected release assets")
    require(all(re.fullmatch(r"[a-f0-9]{64}", str(value)) for value in assets.values()), "Invalid asset digest")
    reviewed = manifest[review_field]
    require(reviewed == {n: assets[n] for n in names} if bundle else reviewed == assets[name], "Exact package content review is required")
    require(all(assets[n] != "a78fb1794fd4f80adc5f54534240f8de1f9fd3cfc18b711cc3af86047e1e7ff1" for n in names), "Withdrawn package")
    require(digest(Path(manifest_path).with_name("release.md").read_bytes()) == manifest["reviewedNotesSha256"], "Exact release notes review is required")
    directory = Path(directory)
    require(not directory.is_symlink() and {p.name for p in directory.iterdir()} == set(assets), "Unexpected asset directory")
    for asset, expected in assets.items():
        p = directory / asset
        require(p.is_file() and not p.is_symlink() and p.stat().st_size <= MAX, "Invalid release asset")
        require(digest(p.read_bytes()) == expected, "Release asset digest mismatch")
    require((directory / "release-signing-key.pub").read_text().strip() == KEY, "Unexpected release key")
    require((directory / "allowed_signers").read_text().strip() == 'publisher namespaces="release" ' + KEY, "Unexpected signer")
    shared_names = [n for n in names if n != linux_name] if multiplatform else names
    checksums = "".join(assets[n] + "  " + n + "\n" for n in sorted(shared_names)).encode()
    require((directory / "SHA256SUMS").read_bytes() == checksums, "Unexpected checksum statement")
    signature = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", str(directory / "allowed_signers"), "-I", "publisher", "-n", "release", "-s", str(directory / "SHA256SUMS.sig")], input=checksums, capture_output=True, timeout=20)
    require(signature.returncode == 0, "Release signature failed")
    if android:
        verify_android(directory / android_name, manifest)
    if recovery:
        verify_android(directory / recovery_name, {"tag": "v" + entry["version"], "android": entry["android"]})
    if not android or bundle:
        verify_windows(directory / windows_name, windows_name, manifest)
    if multiplatform:
        verify_linux_assets(directory, manifest["tag"][1:], assets)
    print("PASS: reviewed platform packages and signatures verified")

if __name__ == "__main__":
    try:
        require(len(sys.argv) == 3, "Usage: verify-release.py MANIFEST ASSET_DIRECTORY")
        verify(sys.argv[1], sys.argv[2])
    except Exception:
        print("Release verification failed", file=sys.stderr)
        sys.exit(1)
