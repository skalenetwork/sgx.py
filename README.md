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
```
You may alter the fields as needed.

Run the tests:
```bash
# Run all tests
pytest

# Run specific test file
pytest ./tests/<test-file-name>.py

```

## License

[![License](https://img.shields.io/github/license/skalenetwork/sgx.py.svg)](LICENSE)

Copyright (C) 2019-present SKALE Labs
