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
from time import sleep

logger = logging.getLogger(__name__)
DEFAULT_TIMEOUT = 10


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


def init_ssl(ssl_dir_path, csr_server):
    csr = read_csr(ssl_dir_path)
    csr_hash = Web3.sha3(text=csr)
    csr_hash = Web3.toHex(csr_hash)
    send_request(csr_server, 'SignCertificate', {'certificate': csr})
    get_certificate(ssl_dir_path, csr_server, csr_hash)


def read_csr(ssl_dir_path):
    csr_path = os.path.join(ssl_dir_path, 'sgx.csr')
    if not os.path.exists(csr_path):
        raise FileNotFoundError('csr file not found')
    with open(csr_path) as f:
        csr = f.read()
    return csr


def get_certificate(ssl_dir_path, csr_server, csr_hash):
    response = send_request(csr_server, 'GetCertificate', {'hash': csr_hash})
    while response['result']['status'] != 0:
        response = send_request(csr_server, 'GetCertificate', {'hash': csr_hash})
        sleep(DEFAULT_TIMEOUT)
    crt = response['result']['cert']
    crt_path = os.path.join(ssl_dir_path, 'sgx.crt')
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
    if not path_to_cert:
        response = requests.post(
            url, data=json.dumps(call_data), headers=headers, verify=False).json()
    else:
        response = requests.post(
            url, data=json.dumps(call_data), headers=headers, verify=path_to_cert).json()
    print(response)
    logger.info(f'Response received: {response["result"]}')
    return response
