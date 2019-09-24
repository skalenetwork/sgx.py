from eth_account import Account
from collections import Mapping
from hexbytes import HexBytes
from eth_account._utils import transactions, signing
from eth_account.datastructures import AttributeDict
from eth_utils.curried import keccak
from cytoolz import dissoc

def sign(transaction_dict, private_key):
    if not isinstance(transaction_dict, Mapping):
        raise TypeError("transaction_dict must be dict-like, got %r" % transaction_dict)

    account = Account.from_key(private_key)

    # allow from field, *only* if it matches the private key
    if 'from' in transaction_dict:
        if transaction_dict['from'] == account.address:
            sanitized_transaction = dissoc(transaction_dict, 'from')
        else:
            raise TypeError("from field must match key's %s, but it was %s" % (
                account.address,
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
    ) = sign_transaction_dict(account._key_obj, sanitized_transaction)

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

    # detect chain
    if isinstance(unsigned_transaction, transactions.UnsignedTransaction):
        chain_id = None
    else:
        chain_id = unsigned_transaction.v

    # sign with private key
    (v, r, s) = signing.sign_transaction_hash(eth_key, transaction_hash, chain_id)

    # serialize transaction with rlp
    encoded_transaction = transactions.encode_transaction(unsigned_transaction, vrs=(v, r, s))

    return (v, r, s, encoded_transaction)

