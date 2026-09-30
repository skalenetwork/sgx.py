#!/usr/bin/env bash

set -euo pipefail
umask 077

CSR_PATH="$1"
KEY_PATH="$2"
COMMON_NAME="$3"

rm -f -- "$CSR_PATH" "$KEY_PATH"

openssl req -new -sha256 -nodes \
    -out "$CSR_PATH" \
    -newkey rsa:2048 \
    -keyout "$KEY_PATH" \
    -subj "/CN=$COMMON_NAME"

chmod 600 "$KEY_PATH"
