import urllib
import os
import secrets

import eth_account._utils.legacy_transactions as transactions
import pytest

from eth_account.messages import defunct_hash_message, encode_defunct

from dotenv import load_dotenv
from eth_keys import keys
from hexbytes import HexBytes
from telnetlib import Telnet
from web3 import Web3


from sgx import SgxClient


load_dotenv()

SGX_URL = os.getenv('SERVER')
GETH_URL = os.getenv('GETH')
ETH_PRIVATE_KEY = os.getenv('ETH_PRIVATE_KEY')

ETH_VALUE_FOR_TESTS = 5 * 10 ** 18


def private_key_to_public(pr):
    pr_bytes = Web3.to_bytes(hexstr=pr)
    pk = keys.PrivateKey(pr_bytes)
    return pk.public_key


def public_key_to_address(pk):
    hash = Web3.keccak(hexstr=str(pk))
    return Web3.to_checksum_address(Web3.to_hex(hash[-20:]))


def private_key_to_address(pr):
    pk = private_key_to_public(pr)
    return public_key_to_address(pk)


@pytest.fixture
def w3():
    return Web3(Web3.HTTPProvider(GETH_URL))


def send_eth_w3(web3, to, value):
    from_address = private_key_to_address(ETH_PRIVATE_KEY)
    nonce = web3.eth.get_transaction_count(from_address)
    tx = {
        'from': from_address,
        'to': to,
        'value': value,
        'gas': 21000,
        'maxFeePerGas': 10 ** 9,
        'maxPriorityFeePerGas': 10,
        'nonce': nonce,
        'chainId': web3.eth.chain_id
    }
    signed = web3.eth.account.sign_transaction(tx, private_key=ETH_PRIVATE_KEY)
    tx_hash = web3.eth.send_raw_transaction(signed.rawTransaction)
    web3.eth.wait_for_transaction_receipt(tx_hash)


@pytest.fixture
def sgx(w3):
    return SgxClient(SGX_URL, os.getenv('CERT_PATH'))


@pytest.fixture
def account(sgx, w3):
    c = SgxClient(SGX_URL, os.getenv('CERT_PATH'))
    generated_key = c.generate_key()
    key = generated_key.name
    address = c.get_account(key).address
    send_eth_w3(w3, address, ETH_VALUE_FOR_TESTS)
    return key, address


def generate_tx(web3, tx_type=None, no_fee=False):
    txn = {
        'to': os.getenv('TEST_ACCOUNT'),
        'value': 0,
        'gas': 200000,
        'gasPrice': web3.eth.gas_price,
        'chainId': web3.eth.chain_id
    }
    if tx_type:
        txn['type'] = tx_type
        if tx_type == 2:
            txn.pop('gasPrice', None)
            txn.update({
                'maxFeePerGas': 10 ** 9,
                'maxPriorityFeePerGas': 10
            })

    return txn


def test_server_connection():
    parsed_url = urllib.parse.urlparse(SGX_URL)
    with Telnet(parsed_url.hostname, parsed_url.port, timeout=5) as tn:
        tn.msg('Test')


def test_sign_and_send(sgx, account, w3):
    key, address = account
    txn = generate_tx(w3)
    txn['nonce'] = w3.eth.get_transaction_count(address)
    signed_txn = sgx.sign(txn, key)
    tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
    w3.eth.wait_for_transaction_receipt(tx_hash)
    assert isinstance(tx_hash, HexBytes)
    assert tx_hash != HexBytes('0x')

    txn_v1 = generate_tx(w3, 1)
    txn_v1['nonce'] = w3.eth.get_transaction_count(address)
    signed_txn = sgx.sign(txn_v1, key)
    tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
    w3.eth.wait_for_transaction_receipt(tx_hash)
    assert isinstance(tx_hash, HexBytes)
    assert tx_hash != HexBytes('0x')


def test_sign_and_send_second_type(sgx, account, w3):
    key, address = account
    txn_v2 = generate_tx(w3, 2)
    txn_v2['nonce'] = w3.eth.get_transaction_count(address)
    signed_txn = sgx.sign(txn_v2, key)
    tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)
    assert isinstance(tx_hash, HexBytes)
    assert tx_hash != HexBytes('0x')


def test_get_info(sgx):
    generated_key = sgx.generate_key()
    assert generated_key.name and generated_key.name[:3] == "NEK"
    assert generated_key.address and len(generated_key.address) == 42
    assert generated_key.public_key and len(generated_key.public_key) == 130
    key = generated_key.name
    account = sgx.get_account(key)
    assert account.public_key and len(account.public_key) == 130
    assert account.address and len(account.address) == 42


def test_get_server_status(sgx):
    assert sgx.get_server_status() == 0


def test_get_server_version(sgx):
    assert isinstance(sgx.get_server_version(), str)


def test_sign_message(sgx, account, w3):
    key, address = account
    txn = generate_tx(w3, tx_type=None, no_fee=True)

    txn['nonce'] = w3.eth.get_transaction_count(address)
    unsigned_transaction = transactions.serializable_unsigned_transaction_from_dict(txn)
    transaction_hash = unsigned_transaction.hash()

    message = defunct_hash_message(transaction_hash).hex()
    signed_message = sgx.sign_hash(message, key, None)
    assert signed_message.messageHash == HexBytes(message)
    assert len(signed_message.signature) > 2
    assert type(signed_message.signature) == HexBytes

    recover_account = w3.eth.account.recover_message(
        encode_defunct(transaction_hash),
        signature=signed_message.signature
    )

    assert recover_account == address


def test_import_ecdsa(sgx, w3):

    random_key_name = secrets.token_hex(32)

    ecdsa_key_name = "NEK:" + random_key_name

    insecure_ecdsa_private_key = "f253bad7b1f62b8ff60bbf451cf2e8e9ebb5d6e9bff450c55b8d5504b8c63d3"

    public_key = sgx.import_ecdsa_private_key(ecdsa_key_name, insecure_ecdsa_private_key)

    assert len(public_key) > 0

    assert public_key == sgx.sgx_rpc_server.get_public_key(ecdsa_key_name)

    account = sgx.get_account(ecdsa_key_name).address

    send_eth_w3(w3, account, ETH_VALUE_FOR_TESTS)

    txn = generate_tx(w3, tx_type=None)
    txn['nonce'] = w3.eth.get_transaction_count(account)
    unsigned_transaction = transactions.serializable_unsigned_transaction_from_dict(txn)
    transaction_hash = unsigned_transaction.hash()
    message = defunct_hash_message(transaction_hash).hex()

    signed_message = sgx.sign_hash(message, ecdsa_key_name, None)
    assert signed_message.messageHash == HexBytes(message)
    assert len(signed_message.signature) > 2
    assert type(signed_message.signature) == HexBytes

    recover_account = w3.eth.account.recover_message(
        encode_defunct(transaction_hash),
        signature=signed_message.signature
    )
    assert recover_account == account
