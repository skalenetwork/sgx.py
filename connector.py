import requests
import json
import os
from dotenv import load_dotenv
load_dotenv()

def ecdsa_sign(keyName, transactionHash):
    url = os.environ['SERVER']
    headers = {'content-type': 'application/json'}

    call_data = {
        "method": "ecdsaSignMessageHash",
        "params": {'base':10, 'keyName': keyName, 'messageHash':transactionHash},
        "jsonrpc": "2.0",
        "id": 0,
    }
    response = requests.post(
        url, data=json.dumps(call_data), headers=headers).json()
    signature = response['result']
    print(signature)
    return(signature['signature_v'], signature['signature_r'], signature['signature_s'])


def generate_key(keyName):
    url = os.environ['SERVER']
    headers = {'content-type': 'application/json'}

    call_data = {
        "method": "generateECDSAKey",
        "params": {'keyName': keyName},
        "jsonrpc": "2.0",
        "id": 0,
    }
    response = requests.post(
        url, data=json.dumps(call_data), headers=headers).json()
    return response


if __name__ == "__main__":
    print(generate_key('key1'))