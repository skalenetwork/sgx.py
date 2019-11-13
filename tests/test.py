from web3 import Web3
from sgx import SgxClient
from random import randint
import os

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
    key = generated_data.keyName
    account = sgx.get_account(key).address
    txn['nonce'] = w3.eth.getTransactionCount(account)
    signed_txn = sgx.sign(txn, key)
    tx = w3.eth.sendRawTransaction(signed_txn.rawTransaction)
    return w3.toHex(tx)


def rename_and_sign():
    temp_key = sgx.generate_key().keyName
    new_key = 'NEK_NODE_ID:' + str(randint(1, 65000))
    sgx.rename_key(temp_key, new_key)
    account = sgx.get_account(new_key).address
    txn['nonce'] = w3.eth.getTransactionCount(account)
    signed_txn = sgx.sign(txn, new_key)
    tx = w3.eth.sendRawTransaction(signed_txn.rawTransaction)
    return w3.toHex(tx)


if __name__ == '__main__':
    print(sign_and_send())
    print(rename_and_sign())
