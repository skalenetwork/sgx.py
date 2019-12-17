import os

PROJECT_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir)
SCRIPTS_DIR = 'scripts'
SCRIPTS_DIR_PATH = os.path.join(PROJECT_DIR, SCRIPTS_DIR)
GENERATE_SCRIPT = 'generate.sh'
GENERATE_SCRIPT_PATH = os.path.join(SCRIPTS_DIR_PATH, GENERATE_SCRIPT)

DEFAULT_TIMEOUT = 10
CERT_PROVIDER_PORT = '1027'

CSR_FILENAME = 'sgx.csr'
KEY_FILENAME = 'sgx.key'
CRT_FILENAME = 'sgx.crt'
