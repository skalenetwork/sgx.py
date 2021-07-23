import urllib
import os
import secrets
from telnetlib import Telnet

from dotenv import load_dotenv
from eth_account._utils import legacy_transactions as transactions
from hexbytes import HexBytes
from web3 import Web3


from sgx import SgxClient


load_dotenv()

SGX_URL = os.getenv('SERVER')
GETH_URL = os.getenv('GETH')

sgx = SgxClient(SGX_URL, os.getenv('CERT_PATH'))
w3 = Web3(Web3.HTTPProvider(GETH_URL))

txn = {
    'to': os.getenv('TEST_ACCOUNT'),
    'value': 0,
    'gas': 2000000,
    'gasPrice': 0,
    'chainId': w3.eth.chainId
}


def test_server_connection():
    parsed_url = urllib.parse.urlparse(SGX_URL)
    with Telnet(parsed_url.hostname, parsed_url.port, timeout=5) as tn:
        tn.msg('Test')


def test_sign_and_send():
    generated_key = sgx.generate_key()
    key = generated_key.name
    account = sgx.get_account(key).address
    txn['nonce'] = w3.eth.getTransactionCount(account)
    signed_txn = sgx.sign(txn, key)
    tx_hash = w3.eth.sendRawTransaction(signed_txn.rawTransaction)
    assert isinstance(tx_hash, HexBytes)
    assert tx_hash != HexBytes('0x')


def test_get_info():
    generated_key = sgx.generate_key()
    assert generated_key.name and generated_key.name[:3] == "NEK"
    assert generated_key.address and len(generated_key.address) == 42
    assert generated_key.public_key and len(generated_key.public_key) == 130
    key = generated_key.name
    account = sgx.get_account(key)
    assert account.public_key and len(account.public_key) == 130
    assert account.address and len(account.address) == 42


def test_get_server_status():
    assert sgx.get_server_status() == 0


def test_get_server_version():
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
    tx_hash = w3.eth.sendRawTransaction(encoded_transaction)
    assert isinstance(tx_hash, HexBytes)
    assert tx_hash != HexBytes('0x')


def test_import_ecdsa():
    sgx = SgxClient(os.environ['SERVER'], path_to_cert=os.environ.get('CERT_PATH'))

    random_key_name = secrets.token_hex(32)

    ecdsa_key_name = "NEK:" + random_key_name

    insecure_ecdsa_private_key = "f253bad7b1f62b8ff60bbf451cf2e8e9ebb5d6e9bff450c55b8d5504b8c63d3"

    public_key = sgx.import_ecdsa_private_key(ecdsa_key_name, insecure_ecdsa_private_key)

    assert len(public_key) > 0

    assert public_key == sgx.sgx_server.get_public_key(ecdsa_key_name)

    account = sgx.get_account(ecdsa_key_name).address
    txn['nonce'] = w3.eth.getTransactionCount(account)
    unsigned_transaction = transactions.serializable_unsigned_transaction_from_dict(txn)
    transaction_hash = unsigned_transaction.hash()
    message = HexBytes(transaction_hash).hex()

    signed_message = sgx.sign_hash(message, ecdsa_key_name, None)
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
    tx_hash = w3.eth.sendRawTransaction(encoded_transaction)
    assert isinstance(tx_hash, HexBytes)
    assert tx_hash != HexBytes('0x')
