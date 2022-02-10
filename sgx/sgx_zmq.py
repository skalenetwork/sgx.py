#    -*- coding: utf-8 -*-
#
#     This file is part of sgx.py
#
#     Copyright (C) 2021 SKALE Labs
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

import binascii
import json
import logging
import os
from dataclasses import dataclass
from enum import Enum
from time import sleep
from sgx.utils import public_key_to_address

from eth_utils.conversions import add_0x_prefix, remove_0x_prefix
import pem
import zmq
from M2Crypto import EVP

from urllib.parse import urlparse

from sgx.constants import (
    DEFAULT_TIMEOUT,
    CRT_FILENAME,
    KEY_FILENAME
)
from sgx.utils import SgxError


logger = logging.getLogger(__name__)


ZMQ_PORT = 1031
MAX_RETRIES = 10


class SgxZmqServerError(SgxError):
    pass


class SgxZmqUnreachableError(SgxError):
    pass


class DkgPolyStatus(Enum):
    FAIL = 0
    NEW_GENERATED = 1
    PREEXISTING = 2


@dataclass
class Account:
    name: str
    address: str
    public_key: str


@dataclass
class ComplaintResponse:
    share: str
    dh_key: str
    verification_vector_mult: str


class SgxZmq:
    def __init__(self, sgx_endpoint, path_to_cert=None, n=None, t=None):
        self.sgx_endpoint = get_provider(sgx_endpoint)
        self.path_to_cert = path_to_cert
        if n:
            self.n = n
        if t:
            self.t = t
        self.cert = self.__read_cert()
        self.ctx = zmq.Context()
        self.__init_method_types()
        self.sockets = dict()

    def __del__(self):
        for socket in self.sockets.values():
            socket.close()
        self.ctx.destroy()

    def ecdsa_sign(self, key_name, transaction_hash):
        params = dict()
        params['base'] = 10
        params['keyName'] = key_name
        params['messageHash'] = transaction_hash
        response = self.__send_request('ecdsaSignMessageHash', params)
        signature = response['result']
        vrs = (signature['signature_v'], signature['signature_r'], signature['signature_s'])
        return vrs

    def generate_key(self):
        params = dict()
        response = self.__send_request("generateECDSAKey", params)
        key_name = response['keyName']
        public_key = response['publicKey']
        public_key = add_0x_prefix(public_key)
        address = public_key_to_address(public_key)
        return Account(
            name=key_name,
            address=address,
            public_key=public_key
        )

    def get_public_key(self, keyName):
        params = dict()
        params['keyName'] = keyName
        response = self.__send_request("getPublicECDSAKey", params)
        publicKey = response['publicKey']
        return publicKey

    def generate_dkg_poly(self, poly_name):
        if self.is_poly_exists(poly_name):
            return DkgPolyStatus.PREEXISTING
        params = dict()
        params['polyName'] = poly_name
        params['t'] = self.t
        response = self.__send_request("generateDKGPoly", params)
        if response['status'] == 0:
            return DkgPolyStatus.NEW_GENERATED
        else:
            return DkgPolyStatus.FAIL

    def get_verification_vector(self, poly_name):
        params = dict()
        params['polyName'] = poly_name
        params['n'] = self.n
        params['t'] = self.t
        response = self.__send_request("getVerificationVector", params)
        verification_vector = response['verificationVector']
        return verification_vector

    def get_secret_key_contribution(self, poly_name, public_keys):
        public_keys = list(map(remove_0x_prefix, public_keys))
        params = dict()
        params['polyName'] = poly_name
        params['n'] = self.n
        params['t'] = self.t
        params['publicKeys'] = public_keys
        response = self.__send_request("getSecretShare", params)
        secret_key_contribution = response['secretShare']
        return secret_key_contribution

    def get_server_status(self):
        response = self.__send_request("getServerStatus")
        return response['status']

    def get_server_version(self):
        response = self.__send_request("getServerVersion")
        return response['version']

    def verify_secret_share(self, public_shares, eth_key_name, secret_share, index):
        params = dict()
        params['publicShares'] = public_shares
        params['ethKeyName'] = eth_key_name
        params['secretShare'] = secret_share
        params['n'] = self.n
        params['t'] = self.t
        params['index'] = index
        response = self.__send_request("dkgVerification", params)
        result = response['result']
        return result

    def create_bls_private_key(self, poly_name, bls_key_name, eth_key_name, secret_shares):
        params = dict()
        params['polyName'] = poly_name
        params['blsKeyName'] = bls_key_name
        params['ethKeyName'] = eth_key_name
        params['secretShare'] = secret_shares
        params['n'] = self.n
        params['t'] = self.t
        response = self.__send_request("createBLSPrivateKey", params)
        return response['status'] == 0

    def get_bls_public_key(self, bls_key_name):
        params = dict()
        params["blsKeyName"] = bls_key_name
        response = self.__send_request("getBLSPublicKeyShare", params)
        return response['blsPublicKeyShare']

    def complaint_response(self, poly_name, idx):
        params = dict()
        params['polyName'] = poly_name
        params['n'] = self.n
        params['t'] = self.t
        params['ind'] = idx
        response = self.__send_request("complaintResponse", params)
        return ComplaintResponse(
            share=response['share*G2'],
            dh_key=response['dhKey'],
            verification_vector_mult=response['verificationVectorMult']
        )

    def mult_g2(self, to_mult):
        params = dict()
        params['x'] = to_mult
        response = self.__send_request("multG2", params)
        return response['x*G2']

    def import_bls_private_key(self, key_share_name, key_share):
        params = dict()
        params['keyShareName'] = key_share_name
        params['keyShare'] = key_share
        response = self.__send_request("importBLSKeyShare", params)
        encrypted_key = response['encryptedKeyShare']
        return encrypted_key

    def is_poly_exists(self, poly_name):
        params = dict()
        params['polyName'] = poly_name
        response = self.__send_request("isPolyExists", params)
        is_exists = response["IsExist"]
        return is_exists

    def delete_bls_key(self, bls_key_name):
        params = dict()
        params['blsKeyName'] = bls_key_name
        response = self.__send_request("deleteBlsKey", params)
        result = response["deleted"]

        return result

    def calculate_all_bls_public_keys(self, verification_vectors):
        params = dict()
        params['t'] = self.t
        params['n'] = self.n
        params['publicShares'] = verification_vectors
        response = self.__send_request("calculateAllBLSPublicKeys", params)
        result = response["publicKeys"]

        return result

    def bls_sign(self, bls_key_name, message_hash):
        params = dict()
        params['keyShareName'] = bls_key_name
        params['messageHash'] = message_hash
        params['t'] = self.t
        params['n'] = self.n
        response = self.__send_request("blsSignMessageHash", params)
        result = response["signatureShare"]

        return result

    def __send_request(self, method, params=None):
        params["type"] = self.method_to_type[method]
        if self.path_to_cert:
            params["cert"] = self.cert
            msgSig = self.__sign_msg(params)
            params["msgSig"] = msgSig
        msg = json.dumps(params, separators=(',', ':'))
        p_id = os.getpid()
        if not self.sockets.get(p_id):
            socket_p_id = self.ctx.socket(zmq.DEALER)
            socket_p_id.setsockopt_string(zmq.IDENTITY, "135:14603077656239261618")
            socket_p_id.setsockopt(zmq.LINGER, 0)
            socket_p_id.connect(self.sgx_endpoint)
            self.sockets[p_id] = socket_p_id
        socket = self.sockets[p_id]
        socket.send_string(msg)
        # await reply
        response_str = None
        for _ in range(MAX_RETRIES):
            try:
                response_str = socket.recv().decode()
            except zmq.ZMQError:
                pass
            if response_str:
                break
            sleep(DEFAULT_TIMEOUT)
        if not response_str:
            raise SgxZmqUnreachableError('Max retries exceeded for sgx connection')
        response = json.loads(response_str)
        if (response.get('errorMessage') is not None and
                len(response.get('errorMessage'))) or response['status']:
            raise SgxZmqServerError(response['errorMessage'])
        return response

    def __sign_msg(self, to_sign):
        msg = json.dumps(to_sign, separators=(',', ':'))
        msg = msg.replace(" ", "")
        key_path = os.path.join(self.path_to_cert, KEY_FILENAME)
        with open(key_path, "r") as key_file:
            private_key = key_file.read()
        key = EVP.load_key_string(private_key.encode())
        key.reset_context(md='sha256')
        key.sign_init()
        key.sign_update(msg.encode())
        return binascii.hexlify(key.sign_final()).decode()

    def __read_cert(self):
        crt_path = os.path.join(self.path_to_cert, CRT_FILENAME)
        crt = pem.parse_file(crt_path)
        return str(crt[0])

    def __init_method_types(self):
        self.method_to_type = dict()
        self.method_to_type["ecdsaSignMessageHash"] = "ECDSASignReq"
        self.method_to_type["generateECDSAKey"] = "generateECDSAReq"
        self.method_to_type["getPublicECDSAKey"] = "getPublicECDSAReq"
        self.method_to_type["generateDKGPoly"] = "generateDKGPolyReq"
        self.method_to_type["getVerificationVector"] = "getVerificationVectorReq"
        self.method_to_type["getSecretShare"] = "getSecretShareReq"
        self.method_to_type["getServerStatus"] = "getServerStatusReq"
        self.method_to_type["getServerVersion"] = "getServerVersionReq"
        self.method_to_type["dkgVerification"] = "dkgVerificationReq"
        self.method_to_type["createBLSPrivateKey"] = "createBLSPrivateReq"
        self.method_to_type["getBLSPublicKeyShare"] = "getBLSPublicReq"
        self.method_to_type["complaintResponse"] = "complaintResponseReq"
        self.method_to_type["importBLSKeyShare"] = "importBLSReq"
        self.method_to_type["isPolyExists"] = "isPolyExistsReq"
        self.method_to_type["deleteBlsKey"] = "deleteBLSKeyReq"
        self.method_to_type["calculateAllBLSPublicKeys"] = "getAllBLSPublicReq"
        self.method_to_type["blsSignMessageHash"] = "BLSSignReq"
        self.method_to_type["multG2"] = "multG2Req"


def get_provider(endpoint):
    parsed_endpoint = urlparse(endpoint)
    ip, _ = parsed_endpoint.netloc.split(':')
    zmq_endpoint = 'tcp://' + ip + ':' + str(ZMQ_PORT)
    return zmq_endpoint
