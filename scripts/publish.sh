#!/usr/bin/env bash
set -ea

: "${PIP_USERNAME?Need to set PIP_USERNAME}"
: "${PIP_PASSWORD?Need to set PIP_PASSWORD}"

if [ $TEST = 1 ]; then
    twine upload --repository testpypi dist/*
else
    echo "Uploading to pypi"
    twine upload -u $PIP_USERNAME -p $PIP_PASSWORD dist/*
fi

echo "==================================================================="
echo "Uploaded to pypi, check at https://pypi.org/project/sgx.py/$VERSION/"
