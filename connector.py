import requests
import json
import os
from dotenv import load_dotenv
load_dotenv()

def main(transactionHash):
    url = os.environ['SERVER']
    headers = {'content-type': 'application/json'}

    payload = {
        "method": "ecdsaSignMessageHash",
        "params": {'keyName':"test_key", 'messageHash':transactionHash},
        "jsonrpc": "2.0",
        "id": 0,
    }
    response = requests.post(
        url, data=json.dumps(payload), headers=headers).json()
    signature = response['result']
    return(signature['signature_v'], signature['signature_r'], signature['signature_s'])


if __name__ == "__main__":
    print(main(hash))