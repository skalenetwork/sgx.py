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

import json
import logging
import os
from enum import Enum
from time import sleep

from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
import zmq

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


class SgxZmq:
    def __init__(self, sgx_endpoint, path_to_cert=None):
        self.sgx_endpoint = get_provider(sgx_endpoint)
        self.path_to_cert = path_to_cert
        self.cert = self.__read_cert()
        self.socket = zmq.Context().socket(zmq.PUB)
        self.socket.connect(self.sgx_endpoint)
        self.__init_method_types()

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
        key_name = response['result']['keyName']
        public_key = response['result']['publicKey']
        return (key_name, public_key)

    def get_public_key(self, keyName):
        params = dict()
        params['keyName'] = keyName
        response = self.__send_request("getPublicECDSAKey", params)
        publicKey = response['result']['publicKey']
        return publicKey

    def generate_dkg_poly(self, poly_name, t):
        if self.is_poly_exist(poly_name):
            return DkgPolyStatus.PREEXISTING
        params = dict()
        params['polyName'] = poly_name
        params['t'] = t
        response = self.__send_request("generateDKGPoly", params)
        if response['result']['status'] == 0:
            return DkgPolyStatus.NEW_GENERATED
        else:
            return DkgPolyStatus.FAIL

    def get_verification_vector(self, poly_name, n, t):
        params = dict()
        params['polyName'] = poly_name
        params['n'] = n
        params['t'] = t
        response = self.__send_request("getVerificationVector", params)
        verification_vector = response['result']['verificationVector']
        return verification_vector

    def get_secret_key_contribution(self, poly_name, public_keys, n, t):
        params = dict()
        params['polyName'] = poly_name
        params['n'] = n
        params['t'] = t
        params['publicKeys'] = public_keys
        response = self.__send_request("getSecretShare", params)
        secret_key_contribution = response['result']['secretShare']
        return secret_key_contribution

    def get_secret_key_contribution_v2(self, poly_name, public_keys, n, t):
        params = dict()
        params['polyName'] = poly_name
        params['n'] = n
        params['t'] = t
        params['publicKeys'] = public_keys
        response = self.__send_request("getSecretShareV2", params)
        secret_key_contribution = response['result']['secretShare']
        return secret_key_contribution

    def get_server_status(self):
        response = self.__send_request("getServerStatus")
        return response['result']['status']

    def get_server_version(self):
        response = self.__send_request("getServerVersion")
        return response['result']['version']

    def verify_secret_share(self, public_shares, eth_key_name, secret_share, n, t, index):
        params = dict()
        params['publicShares'] = public_shares
        params['ethKeyName'] = eth_key_name
        params['secretShare'] = secret_share
        params['n'] = n
        params['t'] = t
        params['index'] = index
        response = self.__send_request("dkgVerification", params)
        result = response['result']
        return result['result']

    def verify_secret_share_v2(self, public_shares, eth_key_name, secret_share, n, t, index):
        params = dict()
        params['publicShares'] = public_shares
        params['ethKeyName'] = eth_key_name
        params['secretShare'] = secret_share
        params['n'] = n
        params['t'] = t
        params['index'] = index
        response = self.__send_request("dkgVerificationV2", params)
        result = response['result']
        return result['result']

    def create_bls_private_key(self, poly_name, bls_key_name, eth_key_name, secret_shares, n, t):
        params = dict()
        params['polyName'] = poly_name
        params['blsKeyName'] = bls_key_name
        params['ethKeyName'] = eth_key_name
        params['secretShare'] = secret_shares
        params['n'] = n
        params['t'] = t
        response = self.__send_request("createBLSPrivateKey", params)
        return response['result']['status'] == 0

    def create_bls_private_key_v2(self, poly_name, bls_key_name, eth_key_name, secret_shares, n, t):
        params = dict()
        params['polyName'] = poly_name
        params['blsKeyName'] = bls_key_name
        params['ethKeyName'] = eth_key_name
        params['secretShare'] = secret_shares
        params['n'] = n
        params['t'] = t
        response = self.__send_request("createBLSPrivateKeyV2", params)
        return response['result']['status'] == 0

    def get_bls_public_key(self, bls_key_name):
        params = dict()
        params["blsKeyName"] = bls_key_name
        response = self.__send_request("getBLSPublicKeyShare", params)
        return response['result']['blsPublicKeyShare']

    def complaint_response(self, poly_name, n, t, idx):
        params = dict()
        params['polyName'] = poly_name
        params['n'] = n
        params['t'] = t
        params['ind'] = idx
        response = self.__send_request("complaintResponse", params)
        return (response['result']['share*G2'], response['result']['dhKey'],
                response['result']['verificationVectorMult']
                )

    def mult_g2(self, to_mult):
        params = dict()
        params['x'] = to_mult
        response = self.__send_request("multG2", params)
        return response['result']['x*G2']

    def import_bls_private_key(self, key_share_name, key_share):
        params = dict()
        params['keyShareName'] = key_share_name
        params['keyShare'] = key_share
        response = self.__send_request("importBLSKeyShare", params)
        encrypted_key = response["result"]['encryptedKeyShare']
        return encrypted_key

    def is_poly_exist(self, poly_name):
        params = dict()
        params['polyName'] = poly_name
        response = self.__send_request("isPolyExists", params)
        is_exists = response["result"]["IsExist"]
        return is_exists

    def delete_bls_key(self, bls_key_name):
        params = dict()
        params['blsKeyName'] = bls_key_name
        response = self.__send_request("deleteBlsKey", params)
        result = response["result"]["deleted"]

        return result

    def calculate_all_bls_public_keys(self, verification_vectors, t, n):
        params = dict()
        params['t'] = t
        params['n'] = n
        params['publicShares'] = verification_vectors
        response = self.__send_request("calculateAllBLSPublicKeys", params)
        result = response["result"]["publicKeys"]

        return result

    def bls_sign(self, bls_key_name, message_hash, t, n):
        params = dict()
        params['keyShareName'] = bls_key_name
        params['messageHash'] = message_hash
        params['t'] = t
        params['n'] = n
        response = self.__send_request("blsSignMessageHash", params)
        result = response["result"]["signatureShare"]

        return result

    def __send_request(self, method, params=None):
        params["type"] = self.method_to_type[method]
        if self.path_to_cert:
            params["cert"] = self.cert
            msgSig = self.__sign_msg(params)
            params["msgSig"] = msgSig
        self.socket.send_json(params)
        # await reply
        response = None
        for _ in range(MAX_RETRIES):
            try:
                response = self.socket.rcv_json()
            except zmq.ZmqError:
                pass
            if response:
                break
            sleep(DEFAULT_TIMEOUT)

        if not response:
            raise SgxZmqUnreachableError('Max retries exceeded for sgx connection')
        if response.get('error') is not None:
            raise SgxZmqServerError(response['error']['message'])
        if response['result']['status']:
            raise SgxZmqServerError(response['result']['errorMessage'])
        return response

    def __sign_msg(self, to_sign):
        msg = json.dumps(to_sign)
        digest = SHA256.new(msg.encode('utf-8'))
        private_key = None
        key_path = os.path.join(self.path_to_cert, KEY_FILENAME)
        with open(key_path, "r") as key_file:
            private_key = RSA.importKey(key_file.read())

        signer = pkcs1_15.new(private_key)
        sig = signer.sign(digest)
        return sig.decode()

    def __read_cert(self):
        crt_path = os.path.join(self.path_to_cert, CRT_FILENAME)
        cert = None
        with open(crt_path, "r") as f:
            cert = f.read()
        return cert

    def __init_method_types(self):
        self.method_to_type = dict()
        self.method_to_type["ecdsaSignMessageHash"] = "ECDSASignReq"
        self.method_to_type["generateECDSAKey"] = "generateECDSAReq"
        self.method_to_type["getPublicECDSAKey"] = "getPublicECDSAReq"
        self.method_to_type["generateDKGPoly"] = "generateDKGPolyReq"
        self.method_to_type["getVerificationVector"] = "getVerificationVectorReq"
        self.method_to_type["getSecretShareV2"] = "getSecretShareReq"
        self.method_to_type["getServerStatus"] = "getServerStatusReq"
        self.method_to_type["getServerVersion"] = "getServerVersionReq"
        self.method_to_type["dkgVerificationV2"] = "dkgVerificationReq"
        self.method_to_type["createBLSPrivateKeyV2"] = "createBLSPrivateReq"
        self.method_to_type["getBLSPublicKeyShare"] = "getBLSPublicReq"
        self.method_to_type["complaintResponse"] = "complaintResponseReq"
        self.method_to_type["importBLSKeyShare"] = "importBLSReq"
        self.method_to_type["isPolyExists"] = "isPolyExistsReq"
        self.method_to_type["deleteBlsKey"] = "deleteBLSKeyReq"
        self.method_to_type["calculateAllBLSPublicKeys"] = "getAllBLSPublicReq"
        self.method_to_type["blsSignMessageHash"] = "BLSSignReq"


def get_provider(endpoint):
    parsed_endpoint = urlparse(endpoint)
    ip, _ = parsed_endpoint.netloc.split(':')
    zmq_endpoint = 'tcp://' + ip + ':' + str(ZMQ_PORT)
    return zmq_endpoint
