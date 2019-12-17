#    -*- coding: utf-8 -*-
#
#     This file is part of sgx.py
#
#     Copyright (C) 2019 SKALE Labs
#
#     sgx.py is free software: you can redistribute it and/or modify
#     it under the terms of the GNU Affero General Public License as published
#     by the Free Software Foundation, either version 3 of the License, or
#     (at your option) any later version.
#
#     sgx.py is distributed in the hope that it will be useful,
#     but WITHOUT ANY WARRANTY; without even the implied warranty of
#     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#     GNU Affero General Public License for more details.
#
#     You should have received a copy of the GNU Affero General Public License
#     along with sgx.py.  If not, see <https://www.gnu.org/licenses/>.

import logging
import sys
import os
import requests
import json
from web3 import Web3
from logging import Formatter, StreamHandler
import subprocess
from sgx.constants import GENERATE_SCRIPT_PATH, DEFAULT_TIMEOUT
import secrets
from time import sleep

logger = logging.getLogger(__name__)


def public_key_to_address(pk):
    hash = Web3.sha3(hexstr=str(pk))
    return Web3.toChecksumAddress(Web3.toHex(hash[-20:]))


def init_default_logger():
    handlers = []
    formatter = Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    stream_handler = StreamHandler(sys.stderr)
    stream_handler.setFormatter(formatter)
    stream_handler.setLevel(logging.INFO)
    handlers.append(stream_handler)

    logging.basicConfig(level=logging.DEBUG, handlers=handlers)


def generate_certificate(crt_dir_path, csr_server):
    key_path = os.path.join(crt_dir_path, 'sgx.key')
    crt_path = os.path.join(crt_dir_path, 'sgx.crt')
    if not os.path.exists(crt_path) or not os.path.exists(key_path):
        csr_path = os.path.join(crt_dir_path, 'sgx.csr')
        if not os.path.exists(csr_path) or not os.path.exists(key_path):
            generate_credentials(csr_path, key_path)
        with open(csr_path) as f:
            csr = f.read()
        csr_hash = Web3.sha3(text=csr)
        csr_hash = Web3.toHex(csr_hash)
        send_request(csr_server, 'SignCertificate', {'certificate': csr})
        write_crt_to_file(crt_path, csr_server, csr_hash)


def generate_credentials(csr_path, key_path):
    certificate_name = secrets.token_hex(nbytes=16)
    subprocess.Popen(["bash", GENERATE_SCRIPT_PATH, key_path, csr_path, certificate_name])


def write_crt_to_file(crt_path, csr_server, csr_hash):
    response = send_request(csr_server, 'GetCertificate', {'hash': csr_hash})
    while response['result']['status'] != 0:
        response = send_request(csr_server, 'GetCertificate', {'hash': csr_hash})
        sleep(DEFAULT_TIMEOUT)
    crt = response['result']['cert']
    with open(crt_path, "w+") as f:
        f.write(crt)


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
        crt_path = os.path.join(path_to_cert, 'sgx.crt')
        key_path = os.path.join(path_to_cert, 'sgx.key')
        response = requests.post(
            url,
            data=json.dumps(call_data),
            headers=headers,
            verify=False,
            cert=(crt_path, key_path)
        ).json()
    else:
        response = requests.post(
            url,
            data=json.dumps(call_data),
            headers=headers
        ).json()
    logger.info(f'Response received: {response}')
    return response
