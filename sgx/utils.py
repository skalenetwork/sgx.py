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
import os
import subprocess
from subprocess import PIPE

from eth_utils import keccak, to_checksum_address, to_hex

logger = logging.getLogger(__name__)

REDACTED = '<redacted>'
SECRET_FIELDS = frozenset({
    'dhKey',
    'key',
    'keyShare',
    'secretContributions',
    'secretShare',
})


class SgxError(Exception):
    pass


def redact(data: object, crop_len: int = 50) -> object:
    if isinstance(data, dict):
        return {
            key: REDACTED if key in SECRET_FIELDS else redact(value, crop_len)
            for key, value in data.items()
        }
    if isinstance(data, list):
        return [redact(item, crop_len) for item in data]
    if isinstance(data, str) and len(data) > crop_len:
        return data[:crop_len] + '...'
    return data


def print_request_log(request):
    logger.info(f'Send request: {redact(request)}')


def print_response_log(response):
    logger.info(f'Response received: {redact(response)}')


def run_cmd(cmd, env=None, shell=False):
    logger.info(f'Running: {cmd}')
    res = subprocess.run(
        cmd, shell=shell, stdout=PIPE, stderr=PIPE,
        env={**os.environ, **(env or {})}
    )
    if res.returncode:
        logger.error('Error during shell execution:')
        logger.error(res.stderr.decode('UTF-8').rstrip())
        raise subprocess.CalledProcessError(res.returncode, cmd)
    return res


def public_key_to_address(pk):
    hash_ = keccak(hexstr=str(pk))
    return to_checksum_address(to_hex(hash_[-20:]))
