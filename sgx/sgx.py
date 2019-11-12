#    -*- coding: utf-8 -*-
#
#     This file is part of sgx.py
#
#     Copyright (C) 2019 SKALE Labs
#
#     sgx.py is free software: you can redistribute it and/or modify
#     it under the terms of the GNU Affero General Public License as published
#     by the Free Software Foundation, either version 3 of the License, or
#     (at your option) any later version.
#
#     sgx.py is distributed in the hope that it will be useful,
#     but WITHOUT ANY WARRANTY; without even the implied warranty of
#     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#     GNU Affero General Public License for more details.
#
#     You should have received a copy of the GNU Affero General Public License
#     along with sgx.py.  If not, see <https://www.gnu.org/licenses/>.

from collections import Mapping
from hexbytes import HexBytes
from eth_account.datastructures import AttributeDict
from eth_utils.curried import keccak
from cytoolz import dissoc
from sgx.sgxRPCHandler import SgxRPCHandler
from sgx.sgx_utils import public_key_to_address
from eth_account._utils import transactions, signing
from eth_utils.encoding import big_endian_to_int


class SgxClient:
    def __init__(self, sgx_endpoint):
        self.sgx_endpoint = sgx_endpoint
        self.sgx_server = SgxRPCHandler(sgx_endpoint)

    def generate_key(self, key_name):
        key = self.sgx_server.generate_key(key_name)
        address = public_key_to_address(key)
        return AttributeDict({
            'address': address,
            'publicKey': key,
        })

    def get_account(self, key_name):
        key = self.sgx_server.get_public_key(key_name)
        address = public_key_to_address(key)
        return AttributeDict({
            'address': address,
            'publicKey': key,
        })

    def sign(self, transaction_dict, key_name):
        if not isinstance(transaction_dict, Mapping):
            raise TypeError("transaction_dict must be dict-like, got %r" % transaction_dict)

        address = self.get_account(key_name).address

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
        ) = self._sign_transaction_dict(key_name, sanitized_transaction)

        transaction_hash = keccak(rlp_encoded)

        return AttributeDict({
            'rawTransaction': HexBytes(rlp_encoded),
            'hash': HexBytes(transaction_hash),
            'r': r,
            's': s,
            'v': v,
        })

    def _sign_transaction_dict(self, eth_key, transaction_dict):
        # generate RLP-serializable transaction, with defaults filled
        unsigned_transaction = transactions.serializable_unsigned_transaction_from_dict(
            transaction_dict)

        transaction_hash = unsigned_transaction.hash()
        # detect chain
        if isinstance(unsigned_transaction, transactions.UnsignedTransaction):
            chain_id = None
        else:
            chain_id = unsigned_transaction.v

        (v, r, s) = self._sign_transaction_hash(eth_key, transaction_hash, chain_id)

        # serialize transaction with rlp
        encoded_transaction = transactions.encode_transaction(
            unsigned_transaction,
            vrs=(v, r, s))

        return (v, r, s, encoded_transaction)

    def _sign_transaction_hash(self, eth_key, transaction_hash, chain_id):
        hash_in_hex = hex(big_endian_to_int(transaction_hash))
        (v_raw, r_raw, s_raw) = self.sgx_server.ecdsa_sign(eth_key, hash_in_hex)
        v = signing.to_eth_v(int(v_raw), chain_id)
        r = int(r_raw)
        s = int(s_raw)
        return (v, r, s)

    def generate_dkg_poly(self, poly_name, t):
        return self.sgx_server.generate_dkg_poly(poly_name, t)

    def get_verification_vector(self, poly_name, n, t):
        return self.sgx_server.get_verification_vector(poly_name, n, t)

    def get_secret_key_contribution(self, poly_name, public_keys, n, t):
        return self.sgx_server.get_secret_key_contribution(poly_name, public_keys, n, t)

    def verify_secret_share(self, public_shares, eth_key_name, secret_share, n, t, index):
        return self.sgx_server.verify_secret_share(
            public_shares,
            eth_key_name,
            secret_share,
            n,
            t,
            index)

    def create_bls_private_key(self, poly_name, bls_key_name, eth_key_name, secret_shares, n, t):
        self.sgx_server.create_bls_private_key(
            poly_name,
            bls_key_name,
            eth_key_name,
            secret_shares,
            n,
            t)

    def import_bls_private_key(self, key_share_name, n, t, index, key_share):
        return self.sgx_server.import_bls_private_key(
            key_share_name,
            n,
            t,
            index,
            key_share)