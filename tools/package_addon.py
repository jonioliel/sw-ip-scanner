"""Create a clean local-install bundle; do not include caches or demo device state."""
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile
import hashlib

root = Path(__file__).resolve().parents[1]
addon = root / "ip_scanner"
output = root / "output"
output.mkdir(exist_ok=True)
destination = output / "ip-scanner-addon-0.1.0.zip"
with ZipFile(destination, "w", ZIP_DEFLATED) as archive:
    archive.write(root / "README.md", "INSTALL.md")
    for path in sorted(addon.rglob("*")):
        if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
            archive.write(path, path.relative_to(root).as_posix())
print(destination)
print("SHA256:", hashlib.sha256(destination.read_bytes()).hexdigest())
