import os
import logging
import secrets
import requests
import json
from time import sleep
from urllib.parse import urlparse

import urllib3
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from sgx.constants import (
    GENERATE_SCRIPT_PATH,
    DEFAULT_TIMEOUT,
    CSR_FILENAME,
    CRT_FILENAME,
    KEY_FILENAME
)
from sgx.utils import run_cmd, print_request_log, print_response_log, SgxError


requests.packages.urllib3.disable_warnings(InsecureRequestWarning)  # TODO: Remove
logger = logging.getLogger(__name__)


MAX_RETRIES = 22


class SgxSSLError(SgxError):
    pass


class SgxUnreachableError(SgxError):
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


def write_crt_to_file(crt_path, csr_server, csr_hash):
    response = send_request_safe(csr_server, 'getCertificate', {'hash': csr_hash})
    while response['result']['status'] == 1:
        response = send_request_safe(csr_server, 'getCertificate', {'hash': csr_hash})
        sleep(DEFAULT_TIMEOUT)
    crt = response['result']['cert']
    with open(crt_path, "w+") as f:
        f.write(crt)


def sign_certificate(csr_server, csr_path):
    with open(csr_path) as csr_file:
        csr = csr_file.read()
    response = send_request_safe(csr_server, 'signCertificate', {'certificate': csr})
    csr_hash = response['result']['hash']
    return csr_hash


def send_request(url, method, params, path_to_cert=None):
    headers = {'content-type': 'application/json'}
    call_data = {
        "id": 0,
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
    }
    print_request_log(call_data)
    cert = None
    if path_to_cert:
        cert = get_certificate_credentials(
            path_to_cert,
            get_cert_provider(url)
        )

    try:
        response = requests.post(
            url,
            data=json.dumps(call_data),
            headers=headers, cert=cert, verify=False
        ).json()
    except requests.exceptions.ConnectionError as err:
        logger.error('Connection to server failed', exc_info=err)
        if isinstance(err.args[0], urllib3.exceptions.MaxRetryError):
            raise SgxUnreachableError('Max retries exceeded for sgx connection')
        raise
    print_response_log(response)
    return response


def send_request_safe(url, method, params=None):
    response = send_request(url, method, params)
    if response.get('error'):
        raise SgxSSLError(response['error']['message'])
    if response['result']['status'] != 0:
        raise SgxSSLError(response['result']['errorMessage'])
    return response


def get_cert_provider(endpoint):
    parsed_endpoint = urlparse(endpoint)
    port = str(parsed_endpoint.port + 1)
    url = 'http://' + parsed_endpoint.hostname + ':' + port
    return url
