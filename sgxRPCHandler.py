import requests
import json
import os
from dotenv import load_dotenv
load_dotenv()

def __send_request(method, params):
    url = os.environ['SERVER']
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


def ecdsa_sign(keyName, transactionHash):
    params = dict()
    params['base'] = 10
    params['keyName'] = keyName
    params['messageHash'] = transactionHash
    response = __send_request('ecdsaSignMessageHash', params)
    signature = response['result']
    vrs = (signature['signature_v'], signature['signature_r'], signature['signature_s'])
    return vrs


def generate_key(keyName):
    params = dict()
    params['keyName'] = keyName
    response = __send_request("generateECDSAKey", params)
    publicKey = response['result']['PublicKey']
    return publicKey


def get_public_key(keyName):
    params = dict()
    params['keyName'] = keyName
    response = __send_request("getPublicECDSAKey", params)
    publicKey = response['result']['PublicKey']
    return publicKey


if __name__ == "__main__":
    print(generate_key('key2'))
    print(get_public_key('key2'))