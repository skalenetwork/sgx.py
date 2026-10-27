#!/usr/bin/env bash

set -euo pipefail

: "${VERSION:?VERSION must be set}"

sed -i "s/^\( *version=\)'[^']*'/\1'${VERSION}'/" setup.py

EXPECTED_VERSION="$(python -c 'import sys; from packaging.version import Version; print(Version(sys.argv[1]))' "$VERSION")"
BUILT_VERSION="$(python setup.py --version)"
if [ "$BUILT_VERSION" != "$EXPECTED_VERSION" ]; then
    echo "Version rewrite failed: setup.py reports '$BUILT_VERSION', expected '$EXPECTED_VERSION'" >&2
    exit 1
fi

rm -rf ./dist/*

python -m build

echo "==================================================================="
echo "Done build: sgx.py $VERSION/"
