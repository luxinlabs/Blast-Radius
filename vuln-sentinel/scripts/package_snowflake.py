"""Build the small, dependency-free source archive imported by the native Snowflake task."""

import zipfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
files = [
    "__init__.py",
    "models.py",
    "config.py",
    "store.py",
    "usecases.py",
    "intel.py",
    "backend.py",
    "service.py",
    "snowflake_runtime.py",
]
out = root / "dist" / "vuln_sentinel.zip"
out.parent.mkdir(exist_ok=True)
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
    for name in files:
        # Fixed timestamp gives deterministic archives and clean source diffs.
        info = zipfile.ZipInfo(f"vuln_sentinel/{name}", date_time=(2026, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(info, (root / "src" / "vuln_sentinel" / name).read_bytes())
print(out)
