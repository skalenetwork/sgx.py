import requests
import json
import os
from dotenv import load_dotenv
load_dotenv()


class SgxRPCHandler:
    def __init__(self, sgx_endpoint):
        self.sgx_endpoint = sgx_endpoint

    def ecdsa_sign(self, keyName, transactionHash):
        params = dict()
        params['base'] = 10
        params['keyName'] = keyName
        params['messageHash'] = transactionHash
        response = self.__send_request('ecdsaSignMessageHash', params)
        signature = response['result']
        vrs = (signature['signature_v'], signature['signature_r'], signature['signature_s'])
        return vrs

    def generate_key(self, keyName):
        params = dict()
        params['keyName'] = keyName
        response = self.__send_request("generateECDSAKey", params)
        publicKey = response['result']['PublicKey']
        return publicKey

    def get_public_key(self, keyName):
        params = dict()
        params['keyName'] = keyName
        response = self.__send_request("getPublicECDSAKey", params)
        publicKey = response['result']['PublicKey']
        return publicKey

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
            url, data=json.dumps(call_data), headers=headers).json()
        return response


if __name__ == "__main__":
    sgx = SgxRPCHandler(os.environ['SERVER'])
    print(sgx.generate_key('key2'))
    print(sgx.get_public_key('key2'))