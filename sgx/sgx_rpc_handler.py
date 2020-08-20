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
from enum import Enum

from urllib.parse import urlparse

from sgx.http import send_request
from sgx.utils import SgxError


logger = logging.getLogger(__name__)


class SgxServerError(SgxError):
    pass


class DkgPolyStatus(Enum):
    FAIL = 0
    NEW_GENERATED = 1
    PREEXISTING = 2


class SgxRPCHandler:
    def __init__(self, sgx_endpoint, path_to_cert):
        self.sgx_endpoint = check_provider(sgx_endpoint)
        self.path_to_cert = path_to_cert

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
        return (response['result']['share*G2'], response['result']['dhKey'])

    def mult_g2(self, to_mult):
        params = dict()
        params['x'] = to_mult
        response = self.__send_request("multG2", params)
        return response['result']['x*G2']

    def import_bls_private_key(self, key_share_name, n, t, index, key_share):
        params = dict()
        params['keyShareName'] = key_share_name
        params['n'] = n
        params['t'] = t
        params['signerIndex'] = index
        params['keyShare'] = key_share
        response = self.__send_request("importBLSKeyShare", params)
        encrypted_key = response['encryptedKeyShare']
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

    def __send_request(self, method, params=None):
        response = send_request(self.sgx_endpoint, method, params, self.path_to_cert)
        if response.get('error') is not None:
            raise SgxServerError(response['error']['message'])
        if response['result']['status']:
            raise SgxServerError(response['result']['errorMessage'])
        return response


def check_provider(endpoint):
    scheme = urlparse(endpoint).scheme
    if scheme == 'http':
        logger.warning(f'Insecure endpoint: {endpoint}')
    if scheme == 'https' or scheme == 'http':
        return endpoint
    raise SgxServerError(
        'Wrong sgx endpoint. Supported schemes: http/https'
    )
