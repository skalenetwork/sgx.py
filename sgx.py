from collections import Mapping
from hexbytes import HexBytes
from eth_account._utils import transactions, signing
from eth_account.datastructures import AttributeDict
from eth_utils.curried import keccak
from eth_utils.encoding import big_endian_to_int
from cytoolz import dissoc
import sgxRPCHandler
from web3 import Web3
from eth_keys.backends.native.ecdsa import ecdsa_raw_verify

public_keys = {}


def generate_key(key_name):
    key = sgxRPCHandler.generate_key(key_name)
    address = public_key_to_address(key)
    return (key,address)


def get_address_from_key(key_name):
    key = get_public_key(key_name)
    return public_key_to_address(key)


# def get_public_key(key_name):
#     if public_keys.get(key_name) == None:
#         public_keys[key_name] = generate_key(key_name)
#     return public_keys[key_name]


def get_public_key(key_name):
    key = sgxRPCHandler.get_public_key(key_name)
    address = public_key_to_address(key)
    return (key, address)


def sign(transaction_dict, key_name):
    if not isinstance(transaction_dict, Mapping):
        raise TypeError("transaction_dict must be dict-like, got %r" % transaction_dict)

    address = get_public_key(key_name)[1]

    # allow from field, *only* if it matches the private key
    if 'from' in transaction_dict:
        if transaction_dict['from'] == address:
            sanitized_transaction = dissoc(transaction_dict, 'from')
        else:
            raise TypeError("from field must match key's %s, but it was %s" % (
                address,
                transaction_dict['from'],
            ))
    else:
        sanitized_transaction = transaction_dict

    # sign transaction
    (
        v,
        r,
        s,
        rlp_encoded,
    ) = sign_transaction_dict(key_name, sanitized_transaction)

    transaction_hash = keccak(rlp_encoded)

    return AttributeDict({
        'rawTransaction': HexBytes(rlp_encoded),
        'hash': HexBytes(transaction_hash),
        'r': r,
        's': s,
        'v': v,
    })


def sign_transaction_dict(eth_key, transaction_dict):
    # generate RLP-serializable transaction, with defaults filled
    unsigned_transaction = transactions.serializable_unsigned_transaction_from_dict(transaction_dict)

    transaction_hash = unsigned_transaction.hash()
    # print('hash:', Web3.toHex(transaction_hash))
    # detect chain
    if isinstance(unsigned_transaction, transactions.UnsignedTransaction):
        chain_id = None
    else:
        chain_id = unsigned_transaction.v

    # sign with private key
    # (v, r, s) = signing.sign_transaction_hash(eth_key, transaction_hash, chain_id)
    (v, r, s) = sign_transaction_hash(eth_key, transaction_hash, chain_id)
    print(v, r, s)
    print('verify:', ecdsa_raw_verify(transaction_hash, (r, s), bytes.fromhex(get_public_key(eth_key)[0])))

    # serialize transaction with rlp
    encoded_transaction = transactions.encode_transaction(unsigned_transaction, vrs=(v, r, s))

    return (v, r, s, encoded_transaction)


def sign_transaction_hash(eth_key, transaction_hash, chain_id):
    # hash_in_hex = Web3.toHex(transaction_hash)
    hash_in_hex = hex(big_endian_to_int(transaction_hash))
    # print(hash_in_hex, len(transaction_hash))
    (v_raw, r_raw, s_raw) = sgxRPCHandler.ecdsa_sign(eth_key, hash_in_hex)
    print('int:',v_raw, r_raw, s_raw)
    print('hex:',hex(int(v_raw)), hex(int(r_raw)), hex(int(s_raw)))
    v = signing.to_eth_v(int(v_raw), chain_id)
    r = int(r_raw)
    s = int(s_raw)
    return (v, r, s)


def public_key_to_address(pk):
    hash = Web3.sha3(hexstr=str(pk))
    return Web3.toChecksumAddress(Web3.toHex(hash[-20:]))








