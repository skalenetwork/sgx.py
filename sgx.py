from collections import Mapping
from hexbytes import HexBytes
from eth_account._utils import transactions, signing
from eth_account.datastructures import AttributeDict
from eth_utils.curried import keccak
from eth_utils.encoding import big_endian_to_int
from cytoolz import dissoc
from sgxRPCHandler import SgxRPCHandler
from web3 import Web3

public_keys = {}

class SgxClient:
    def __init__(self, sgx_endpoint):
        self.sgx_endpoint = sgx_endpoint
        self.sgxRPCHandler = SgxRPCHandler(sgx_endpoint)

    def generate_key(self, key_name):
        key = self.sgxRPCHandler.generate_key(key_name)
        address = self.public_key_to_address(key)
        return (key,address)


    def get_public_key(self, key_name):
        key = self.sgxRPCHandler.get_public_key(key_name)
        address = self.public_key_to_address(key)
        return (key, address)


    def sign(self, transaction_dict, key_name):
        if not isinstance(transaction_dict, Mapping):
            raise TypeError("transaction_dict must be dict-like, got %r" % transaction_dict)

        address = self.sgxRPCHandler.get_public_key(key_name)[1]

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
        ) = self.sign_transaction_dict(key_name, sanitized_transaction)

        transaction_hash = keccak(rlp_encoded)

        return AttributeDict({
            'rawTransaction': HexBytes(rlp_encoded),
            'hash': HexBytes(transaction_hash),
            'r': r,
            's': s,
            'v': v,
        })


    def sign_transaction_dict(self, eth_key, transaction_dict):
        # generate RLP-serializable transaction, with defaults filled
        unsigned_transaction = transactions.serializable_unsigned_transaction_from_dict(transaction_dict)

        transaction_hash = unsigned_transaction.hash()
        # detect chain
        if isinstance(unsigned_transaction, transactions.UnsignedTransaction):
            chain_id = None
        else:
            chain_id = unsigned_transaction.v

        (v, r, s) = self.sign_transaction_hash(eth_key, transaction_hash, chain_id)

        # serialize transaction with rlp
        encoded_transaction = transactions.encode_transaction(unsigned_transaction, vrs=(v, r, s))

        return (v, r, s, encoded_transaction)


    def sign_transaction_hash(self, eth_key, transaction_hash, chain_id):
        hash_in_hex = hex(big_endian_to_int(transaction_hash))
        (v_raw, r_raw, s_raw) = self.sgxRPCHandler.ecdsa_sign(eth_key, hash_in_hex)
        v = signing.to_eth_v(int(v_raw), chain_id)
        r = int(r_raw)
        s = int(s_raw)
        return (v, r, s)


    def public_key_to_address(self, pk):
        hash = Web3.sha3(hexstr=str(pk))
        return Web3.toChecksumAddress(Web3.toHex(hash[-20:]))








