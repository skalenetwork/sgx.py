import os
import logging
import secrets
import requests
import json
from urllib.parse import urlparse
from time import sleep
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from sgx.constants import (
    GENERATE_SCRIPT_PATH,
    DEFAULT_TIMEOUT,
    CSR_FILENAME,
    CRT_FILENAME,
    KEY_FILENAME
)
from sgx.utils import run_cmd, print_request_log, print_response_log


requests.packages.urllib3.disable_warnings(InsecureRequestWarning)  # TODO: Remove
logger = logging.getLogger(__name__)


MAX_RETRIES = 23


class SgxSSLError(Exception):
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


def retry_request(request_func, *args, **kwargs):
    timeouts = [2 ** i for i in range(MAX_RETRIES)]
    response = None
    error = None

    for i, timeout in enumerate(timeouts):
        logger.debug(f'Sending request to sgx. Try {i}')
        try:
            response = request_func(*args, **kwargs).json()
        except requests.exceptions.ConnectionError as err:
            logger.error(f'Connection to server failed. try {i}', exc_info=err)
            error = err
            continue
        else:
            error = None
            break

    if error is not None:
        raise error
    return response


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

    response = retry_request(
        requests.post,
        url,
        data=json.dumps(call_data),
        headers=headers, cert=cert, verify=False
    )
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
