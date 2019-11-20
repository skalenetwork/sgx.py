from web3 import Web3
from sgx import SgxClient
from dotenv import load_dotenv

import os

load_dotenv()

w3 = Web3(Web3.HTTPProvider(os.environ['GETH']))
sgx = SgxClient(os.environ['SERVER'])

txn = {
    'to': os.environ['TEST_ACCOUNT'],
    'value': 0,
    'gas': 2000000,
    'gasPrice': 0,
    'chainId': 1
}

MAX_NODE_ID = 65000


def sign_and_send():
    generated_data = sgx.generate_key()
    key = generated_data.key_name
    account = sgx.get_account(key).address
    txn['nonce'] = w3.eth.getTransactionCount(account)
    signed_txn = sgx.sign(txn, key)
    tx = w3.eth.sendRawTransaction(signed_txn.rawTransaction)
    return w3.toHex(tx)


def get_info():
    generated_data = sgx.generate_key()
    assert generated_data.key_name
    assert generated_data.address
    assert generated_data.public_key
    key = generated_data.key_name
    account = sgx.get_account(key)
    assert account.public_key
    assert account.address
    return account


if __name__ == '__main__':
    print(sign_and_send())
    print(get_info())