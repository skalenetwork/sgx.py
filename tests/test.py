from web3 import Web3
from sgx import SgxClient
from dotenv import load_dotenv

import os

load_dotenv()

w3 = Web3(Web3.HTTPProvider(os.environ['GETH']))
sgx = SgxClient(os.environ['SERVER'], os.environ['CERT_PATH'])

txn = {
    'to': os.environ['TEST_ACCOUNT'],
    'value': 0,
    'gas': 2000000,
    'gasPrice': 0,
    'chainId': 1
}


def sign_and_send():
    generated_key = sgx.generate_key()
    key = generated_key.name
    account = sgx.get_account(key).address
    txn['nonce'] = w3.eth.getTransactionCount(account)
    signed_txn = sgx.sign(txn, key)
    tx = w3.eth.sendRawTransaction(signed_txn.rawTransaction)
    return w3.toHex(tx)


def get_info():
    generated_key = sgx.generate_key()
    assert generated_key.name and generated_key.name[:3] == "NEK"
    assert generated_key.address and len(generated_key.address) == 42
    assert generated_key.public_key and len(generated_key.public_key) == 130
    key = generated_key.name
    account = sgx.get_account(key)
    assert account.public_key and len(account.public_key) == 130
    assert account.address and len(account.address) == 42
    return account


if __name__ == '__main__':
    print(sign_and_send())
    print(get_info())
