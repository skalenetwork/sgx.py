from hexbytes import HexBytes
from web3 import Web3
from sgx import SgxClient
from dotenv import load_dotenv

from eth_account._utils import transactions

import os

load_dotenv()

w3 = Web3(Web3.HTTPProvider(os.environ['GETH']))
sgx = SgxClient(os.environ['SERVER'], os.environ.get('CERT_PATH'))

txn = {
    'to': os.environ['TEST_ACCOUNT'],
    'value': 0,
    'gas': 2000000,
    'gasPrice': 0,
    'chainId': w3.eth.chainId
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


def get_server_status():
    assert sgx.get_server_status() == 0


def get_server_version():
    assert isinstance(sgx.get_server_version(), str)


def test_sign_message():
    generated_key = sgx.generate_key()
    key = generated_key.name
    account = sgx.get_account(key).address
    txn['nonce'] = w3.eth.getTransactionCount(account)
    unsigned_transaction = transactions.serializable_unsigned_transaction_from_dict(txn)
    transaction_hash = unsigned_transaction.hash()
    message = HexBytes(transaction_hash).hex()

    signed_message = sgx.sign_hash(message, key, None)
    assert signed_message.messageHash == HexBytes(message)
    assert len(signed_message.signature) > 2
    assert type(signed_message.signature) == HexBytes

    recover_account = w3.eth.account.recoverHash(
        signed_message.messageHash,
        signature=signed_message.signature
    )
    assert recover_account == account

    encoded_transaction = transactions.encode_transaction(
        unsigned_transaction,
        vrs=(signed_message.v, signed_message.r, signed_message.s))
    tx = w3.eth.sendRawTransaction(encoded_transaction)
    return w3.toHex(tx)


if __name__ == '__main__':
    print(sign_and_send())
    print(get_info())
    get_server_status()
    get_server_version()
    print(test_sign_message())
