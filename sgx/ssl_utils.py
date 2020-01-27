import os
import logging
import secrets
import subprocess
import requests
import json
from urllib.parse import urlparse
from time import sleep
from subprocess import PIPE
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from sgx.constants import (
    GENERATE_SCRIPT_PATH,
    DEFAULT_TIMEOUT,
    CSR_FILENAME,
    CRT_FILENAME,
    KEY_FILENAME
)

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)  # TODO: Remove
logger = logging.getLogger(__name__)


class SgxSSLException(Exception):
    pass


def get_certificate_credentials(crt_dir_path, csr_server):
    key_path = os.path.join(crt_dir_path, KEY_FILENAME)
    crt_path = os.path.join(crt_dir_path, CRT_FILENAME)
    if not os.path.exists(crt_path) or not os.path.exists(key_path):
        csr_path = os.path.join(crt_dir_path, CSR_FILENAME)
        if not os.path.exists(csr_path) or not os.path.exists(key_path):
            generate_csr_credentials(csr_path, key_path)
        csr_hash = sign_certificate(csr_server, csr_path)
        write_crt_to_file(crt_path, csr_server, csr_hash)
    return crt_path, key_path


def generate_csr_credentials(csr_path, key_path):
    certificate_name = secrets.token_hex(nbytes=32)
    run_cmd(["bash", GENERATE_SCRIPT_PATH, csr_path, key_path, certificate_name])


def run_cmd(cmd, env={}, shell=False):
    logger.info(f'Running: {cmd}')
    res = subprocess.run(cmd, shell=shell, stdout=PIPE, stderr=PIPE, env={**env, **os.environ})
    if res.returncode:
        logger.error('Error during shell execution:')
        logger.error(res.stderr.decode('UTF-8').rstrip())
        raise subprocess.CalledProcessError(res.returncode, cmd)
    return res


def write_crt_to_file(crt_path, csr_server, csr_hash):
    response = send_request(csr_server, 'getCertificate', {'hash': csr_hash})
    while response['result']['status'] == 1:
        response = send_request(csr_server, 'getCertificate', {'hash': csr_hash})
        sleep(DEFAULT_TIMEOUT)
    if response['result']['status'] != 0:
        raise SgxSSLException(response['result']['errorMessage'])
    crt = response['result']['cert']
    with open(crt_path, "w+") as f:
        f.write(crt)


def sign_certificate(csr_server, csr_path):
    with open(csr_path) as csr_file:
        csr = csr_file.read()
    response = send_request(csr_server, 'signCertificate', {'certificate': csr})
    if response['result']['status'] != 0:
        raise SgxSSLException(response['result']['errorMessage'])
    csr_hash = response['result']['hash']
    return csr_hash


def send_request(url, method, params, path_to_cert=None):
    headers = {'content-type': 'application/json'}
    call_data = {
        "method": method,
        "params": params,
        "jsonrpc": "2.0",
        "id": 0,
    }
    logger.info(f'Send request: {method}, {params}')
    if path_to_cert:
        cert_provider = get_cert_provider(url)
        response = requests.post(
            url,
            data=json.dumps(call_data),
            headers=headers,
            verify=False,
            cert=get_certificate_credentials(path_to_cert, cert_provider)
        ).json()
    else:
        response = requests.post(
            url,
            data=json.dumps(call_data),
            headers=headers,
            verify=False
        ).json()
    logger.info(f'Response received: {response}')
    return response


def get_cert_provider(endpoint):
    parsed_endpoint = urlparse(endpoint)
    port = str(parsed_endpoint.port+1)
    url = 'http://' + parsed_endpoint.hostname + ':' + port
    return url
