#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
mkdir -p build
python3 -m venv --clear build/venv
build/venv/bin/python -m pip install --quiet -r requirements.txt
site_packages=$(build/venv/bin/python -c 'import sysconfig; print(sysconfig.get_path("purelib"))')
cp -R lambda_functions contracts "$site_packages/"
build/venv/bin/python - "$site_packages" "$PWD/build/lambda_functions.zip" <<'PY'
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

source = Path(sys.argv[1])
with ZipFile(sys.argv[2], "w", compression=ZIP_DEFLATED) as archive:
    for path in source.rglob("*"):
        relative = path.relative_to(source)
        if (path.is_file() and "__pycache__" not in relative.parts and path.suffix != ".pyc"
                and relative.parts[0] != "pip" and not relative.parts[0].startswith("pip-")):
            archive.write(path, relative)
PY