# sgx.py
[![Discord](https://img.shields.io/discord/534485763354787851.svg)](https://discord.gg/vvUtWJB)

## Requirements

|**Tool**|**Minimum Supported Version**|
|--------|-----------|
| Python |    3.11    |

---

## Installation

### Install Python 3.11

```bash
# confirm prerequisites are isntalled
sudo apt update
sudo apt install software-properties-common
# Add deadsnakes PPA - widely used for Python versions
sudo add-apt-repository ppa:deadsnakes/ppa
# update again & install python 3.11
sudo apt update
sudo apt install python3.11
# Check if it was installed
python3.11 --version 

pip install sgx.py
```
--- 

## Developers
### Install all python libraries
```bash
sudo apt-get update --fix-missing
sudo apt-get install libudev-dev
sudo apt-get install swig

# create virtual environment - install dependencies locally
python3.11 -m venv venv
source venv/bin/activate
pip install -e .
pip install -e .[dev]
```

### Running Tests

Create a `.env` file in source directory, like the following:
```bash
SERVER=https://127.0.0.1:1026
CERT_PATH=.
ETH_PRIVATE_KEY=
GETH=
# 1 when sgxwallet runs with -e (ZMQ key ownership)
SGX_EXPECT_ZMQ_OWNERSHIP=0
```
You may alter the fields as needed.

Run the tests:
```bash
# Run all tests
pytest

# Run specific test file
pytest ./tests/<test-file-name>.py

```

## Checking the wallet

Available from sgxwallet 1.11.0. Older servers raise `SgxMethodNotFoundError`, a subclass of `SgxServerError`.

### Client certificate

```python
from sgx import CertificateMatch, SgxClient

client = SgxClient(endpoint, cert_dir, allow_registration=False)
check = client.check_local_certificate(expected_number=1)
if check.outcome is not CertificateMatch.MATCH:
    print(check.outcome, check.newer_issued_at)
```

| `check.outcome` | Meaning |
|---|---|
| `MATCH` | `sgx.crt` is the newest certificate the wallet issued, and the wallet issued `expected_number` client certificates |
| `UNEXPECTED_NUMBER` | `sgx.crt` is the newest, but the number of issued certificates differs |
| `NOT_LATEST` | the wallet issued a newer certificate, at `check.newer_issued_at` |
| `NOT_ISSUED` | unknown to the wallet's CA: wrong endpoint, or its CA database was recreated |

`check.info` holds both counts and the newest certificate with its status: `V`, `R` or `E`. The check relies on the server verifying client certificates; otherwise `NOT_LATEST` can also mean a certificate from another CA.

Unless `allow_registration=False` is passed, any request registers a new certificate when `sgx.crt` or `sgx.key` is missing, and the constructor makes such a request when the directory does not hold exactly three files. `check_local_certificate` never registers.

### Server options

```python
options = client.get_server_options()
options.effective.zmq_key_ownership_enforced  # -e is in effect; applies to ZMQ only
```

The server reports these values itself; they are not attested. `options.build` is `None` unless the server verifies the caller's certificate. While sgxwallet starts or stops, the call raises `SgxServerError`; retry.

## License

[![License](https://img.shields.io/github/license/skalenetwork/sgx.py.svg)](LICENSE)

Copyright (C) 2019-present SKALE Labs
