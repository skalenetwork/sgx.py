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
from web3 import Web3
from logging import Formatter, StreamHandler

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
