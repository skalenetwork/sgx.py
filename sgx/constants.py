import os

CUR_DIR = os.path.dirname(os.path.realpath(__file__))
GENERATE_SCRIPT_PATH = os.path.join(CUR_DIR, 'generate.sh')

DEFAULT_TIMEOUT = 10

CSR_FILENAME = 'sgx.csr'
KEY_FILENAME = 'sgx.key'
CRT_FILENAME = 'sgx.crt'
