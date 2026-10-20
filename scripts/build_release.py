"""Package versioned source and briefing files, excluding old archives and local state."""
from pathlib import Path
import hashlib
import json
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]
NAME = 'VulnSuite_v0.4_updated_2026-10-21.zip'


def build():
    paths = subprocess.check_output(
        ['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard'], cwd=ROOT
    ).decode().split('\0')
    entries = {}
    for name in sorted(set(paths)):
        path = Path(name)
        if not name or not (ROOT / path).is_file():
            continue
        if path.suffix in {'.zip', '.sha256'} or name.startswith('collateral/archive/'):
            continue
        if any(part in {'.git', '.venv', '.tools', 'runtime', '__pycache__', '.pytest_cache'} for part in path.parts):
            raise ValueError(f'Local state must not be versioned: {name}')
        if path.suffix in {'.pem', '.key', '.db', '.sqlite', '.sqlite3'} or path.name == '.env':
            raise ValueError(f'Private runtime file must not be packaged: {name}')
        entries[name] = (ROOT / path).read_bytes()
    manifest = {name: hashlib.sha256(data).hexdigest() for name, data in entries.items()}
    with zipfile.ZipFile(ROOT / NAME, 'w', zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries.items():
            info = zipfile.ZipInfo('VulnSuite/' + name, date_time=(2026, 10, 21, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = ((ROOT / name).stat().st_mode & 0xffff) << 16
            archive.writestr(info, data)
        archive.writestr('VulnSuite/RELEASE_MANIFEST.json', json.dumps(manifest, indent=2) + '\n')
    with zipfile.ZipFile(ROOT / NAME) as archive:
        assert archive.testzip() is None
        for name, digest in manifest.items():
            assert hashlib.sha256(archive.read('VulnSuite/' + name)).hexdigest() == digest
            assert archive.read('VulnSuite/' + name) == (ROOT / name).read_bytes()
    checksum = hashlib.sha256((ROOT / NAME).read_bytes()).hexdigest()
    (ROOT / (NAME + '.sha256')).write_text(f'{checksum}  {NAME}\n')
    print(f'Verified {len(entries)} files; SHA256 {checksum}')


if __name__ == '__main__':
    build()
