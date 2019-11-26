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

import requests
import json
from urllib.parse import urlparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)  # TODO: Remove


class SgxRPCHandler:
    def __init__(self, sgx_endpoint):
        self.sgx_endpoint = check_provider(sgx_endpoint)

    def ecdsa_sign(self, keyName, transactionHash):
        params = dict()
        params['base'] = 10
        params['keyName'] = keyName
        params['messageHash'] = transactionHash
        response = self.__send_request('ecdsaSignMessageHash', params)
        signature = response['result']
        vrs = (signature['signature_v'], signature['signature_r'], signature['signature_s'])
        return vrs

    def generate_key(self):
        params = dict()
        response = self.__send_request("generateECDSAKey", params)
        key_name = response['result']['KeyName']
        public_key = response['result']['PublicKey']
        return (key_name, public_key)

    def get_public_key(self, keyName):
        params = dict()
        params['keyName'] = keyName
        response = self.__send_request("getPublicECDSAKey", params)
        publicKey = response['result']['PublicKey']
        return publicKey

    def generate_dkg_poly(self, poly_name, t):
        params = dict()
        params['polyName'] = poly_name
        params['t'] = t
        response = self.__send_request("generateDKGPoly", params)
        return response['result']['status'] == 0

    def get_verification_vector(self, poly_name, n, t):
        params = dict()
        params['polyName'] = poly_name
        params['n'] = n
        params['t'] = t
        response = self.__send_request("getVerificationVector", params)
        verification_vector = response['result']['Verification Vector']
        return verification_vector

    def get_secret_key_contribution(self, poly_name, public_keys, n, t):
        params = dict()
        params['polyName'] = poly_name
        params['n'] = n
        params['t'] = t
        params['publicKeys'] = public_keys
        response = self.__send_request("getSecretShare", params)
        secret_key_contribution = response['result']['SecretShare']
        return secret_key_contribution

    def verify_secret_share(self, public_shares, eth_key_name, secret_share, n, t, index):
        params = dict()
        params['publicShares'] = public_shares
        params['EthKeyName'] = eth_key_name
        params['SecretShare'] = secret_share
        params['n'] = n
        params['t'] = t
        params['index'] = index
        response = self.__send_request("DKGVerification", params)
        result = response['result']
        return result['result']

    def create_bls_private_key(self, poly_name, bls_key_name, eth_key_name, secret_shares, n, t):
        params = dict()
        params['polyName'] = poly_name
        params['BLSKeyName'] = bls_key_name
        params['EthKeyName'] = eth_key_name
        params['SecretShare'] = secret_shares
        params['n'] = n
        params['t'] = t
        response = self.__send_request("CreateBLSPrivateKey", params)
        return response['result']['status'] == 0

    def get_bls_public_key(self, bls_key_name):
        params = dict()
        params["BLSKeyName"] = bls_key_name
        response = self.__send_request("GetBLSPublicKeyShare", params)
        return response['result']['BLSPublicKeyShare']

    def complaint_response(self, poly_name, n, t, idx):
        params = dict()
        params['polyName'] = poly_name
        params['n'] = n
        params['t'] = t
        params['ind'] = idx
        response = self.__send_request("ComplaintResponse", params)
        return (response['result']['share*G2'], response['result']['DHKey'])

    def import_bls_private_key(self, key_share_name, n, t, index, key_share):
        params = dict()
        params['keyShareName'] = key_share_name
        params['n'] = n
        params['t'] = t
        params['index'] = index
        params['key_share'] = key_share
        response = self.__send_request("ImportBLSKeyShare", params)
        encrypted_key = response['encryptedKeyShare']
        return encrypted_key

    def __send_request(self, method, params):
        url = self.sgx_endpoint
        headers = {'content-type': 'application/json'}
        call_data = {
            "method": method,
            "params": params,
            "jsonrpc": "2.0",
            "id": 0,
        }
        response = requests.post(
            url, data=json.dumps(call_data), headers=headers, verify=False).json()
        if response.get('error') is not None:
            raise Exception(response['error']['message'])
        if response['result']['status']:
            raise Exception(response['result']['errorMessage'])
        return response


def check_provider(endpoint):
    scheme = urlparse(endpoint).scheme
    if scheme == 'https':
        return endpoint
    raise Exception(
        'Wrong sgx endpoint. Supported schemes: https'
    )
