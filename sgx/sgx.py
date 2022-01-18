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

import logging
from dataclasses import dataclass
from collections import Mapping
from hexbytes import HexBytes
from eth_account.datastructures import SignedTransaction, SignedMessage
from eth_utils.curried import keccak
from cytoolz import dissoc
from sgx.sgx_rpc_handler import SgxRPCHandler
from sgx.sgx_zmq import SgxZmq
from sgx.utils import public_key_to_address
from eth_account._utils import signing
from eth_account._utils.legacy_transactions import encode_transaction
from eth_account._utils.typed_transactions import TypedTransaction
from eth_utils.encoding import big_endian_to_int
from eth_utils.conversions import add_0x_prefix, remove_0x_prefix

logger = logging.getLogger(__name__)


@dataclass
class Account:
    name: str
    address: str
    public_key: str


@dataclass
class ComplaintResponse:
    share: str
    dh_key: str
    verification_vector_mult: str


class SgxClient:
    def __init__(self, sgx_endpoint, path_to_cert=None, n=None, t=None, zmq=False):
        self.sgx_endpoint = sgx_endpoint
        self.sgx_rpc_server = SgxRPCHandler(sgx_endpoint, path_to_cert)
        if zmq:
            self.zmq = SgxZmq(sgx_endpoint, path_to_cert, n, t)
        if not path_to_cert:
            logger.warning('Using SgxClient without certificates')
        if n:
            self.n = n
        if t:
            self.t = t

    def generate_key(self):
        key_name, public_key = self.sgx_rpc_server.generate_key()
        public_key = add_0x_prefix(public_key)
        address = public_key_to_address(public_key)
        return Account(
            name=key_name,
            address=address,
            public_key=public_key
        )

    def get_account(self, key_name):
        key = self.sgx_rpc_server.get_public_key(key_name)
        key = add_0x_prefix(key)
        address = public_key_to_address(key)
        return Account(
            name=key_name,
            address=address,
            public_key=key
        )

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
        return SignedTransaction(
            rawTransaction=HexBytes(rlp_encoded),
            hash=HexBytes(transaction_hash),
            r=r,
            s=s,
            v=v
        )

    def sign_hash(self, message, key_name, chain_id):
        msg_hash_bytes = HexBytes(message)
        if len(msg_hash_bytes) != 32:
            raise ValueError("The message hash must be exactly 32-bytes")

        (v, r, s) = self._sign_hash(
            key_name,
            msg_hash_bytes,
            chain_id,
            eip_1559_identifier=False
        )
        signature_bytes = signing.to_bytes32(r) + signing.to_bytes32(s) + signing.to_bytes(v)
        return SignedMessage(
            messageHash=msg_hash_bytes,
            r=r,
            s=s,
            v=v,
            signature=HexBytes(signature_bytes)
        )

    def generate_dkg_poly(self, poly_name):
        return self.sgx_rpc_server.generate_dkg_poly(poly_name, self.t)

    def get_verification_vector(self, poly_name):
        return self.sgx_rpc_server.get_verification_vector(poly_name, self.n, self.t)

    def get_secret_key_contribution(self, poly_name, public_keys):
        public_keys = list(map(remove_0x_prefix, public_keys))
        return self.sgx_rpc_server.get_secret_key_contribution(
            poly_name, public_keys, self.n, self.t
        )

    def get_secret_key_contribution_v2(self, poly_name, public_keys):
        public_keys = list(map(remove_0x_prefix, public_keys))
        return self.sgx_rpc_server.get_secret_key_contribution_v2(
            poly_name, public_keys, self.n, self.t
        )

    def get_server_status(self):
        return self.sgx_rpc_server.get_server_status()

    def get_server_version(self):
        return self.sgx_rpc_server.get_server_version()

    def verify_secret_share(self, public_shares, eth_key_name, secret_share, index):
        return self.sgx_rpc_server.verify_secret_share(
            public_shares,
            eth_key_name,
            secret_share,
            self.n,
            self.t,
            index)

    def verify_secret_share_v2(self, public_shares, eth_key_name, secret_share, index):
        return self.sgx_rpc_server.verify_secret_share_v2(
            public_shares,
            eth_key_name,
            secret_share,
            self.n,
            self.t,
            index)

    def create_bls_private_key(self, poly_name, bls_key_name, eth_key_name, secret_shares):
        return self.sgx_rpc_server.create_bls_private_key(
            poly_name,
            bls_key_name,
            eth_key_name,
            secret_shares,
            self.n,
            self.t)

    def create_bls_private_key_v2(self, poly_name, bls_key_name, eth_key_name, secret_shares):
        return self.sgx_rpc_server.create_bls_private_key_v2(
            poly_name,
            bls_key_name,
            eth_key_name,
            secret_shares,
            self.n,
            self.t)

    def get_bls_public_key(self, bls_key_name):
        return self.sgx_rpc_server.get_bls_public_key(bls_key_name)

    def complaint_response(self, poly_name, idx):
        share, dh_key, verification_vector_mult = self.sgx_rpc_server.complaint_response(
            poly_name, self.n, self.t, idx
        )
        return ComplaintResponse(
            share=share,
            dh_key=dh_key,
            verification_vector_mult=verification_vector_mult
        )

    def mult_g2(self, to_mult):
        return self.sgx_rpc_server.mult_g2(to_mult)

    def import_bls_private_key(self, key_share_name, key_share):
        return self.sgx_rpc_server.import_bls_private_key(key_share_name, key_share)

    def import_ecdsa_private_key(self, key_share_name, key_share):
        return self.sgx_rpc_server.import_ecdsa_private_key(key_share_name, key_share)

    def is_poly_exists(self, poly_name):
        return self.sgx_rpc_server.is_poly_exist(poly_name)

    def delete_bls_key(self, bls_key_name):
        return self.sgx_rpc_server.delete_bls_key(bls_key_name)

    def calculate_all_bls_public_keys(self, verification_vectors):
        return self.sgx_rpc_server.calculate_all_bls_public_keys(
            verification_vectors, self.t, self.n
        )

    def bls_sign(self, bls_key_name, message_hash):
        return self.sgx_rpc_server.bls_sign(bls_key_name, message_hash, self.t, self.n)

    def _sign_transaction_dict(self, eth_key, transaction_dict):
        # generate RLP-serializable transaction, with defaults filled
        unsigned_tx = signing.serializable_unsigned_transaction_from_dict(
            transaction_dict
        )

        transaction_hash = unsigned_tx.hash()

        chain_id = transaction_dict['chainId']

        eip_1559_identifier = False

        if isinstance(unsigned_tx, TypedTransaction):
            eip_1559_identifier = True

        (v, r, s) = self._sign_hash(
            eth_key,
            transaction_hash,
            chain_id,
            eip_1559_identifier
        )

        # serialize transaction with rlp
        encoded_tx = encode_transaction(
            unsigned_tx,
            vrs=(v, r, s))

        return v, r, s, encoded_tx

    def _sign_hash(
        self,
        eth_key,
        transaction_hash,
        chain_id,
        eip_1559_identifier=False
    ):
        hash_in_hex = hex(big_endian_to_int(transaction_hash))
        (v_raw, r_raw, s_raw) = self.sgx_rpc_server.ecdsa_sign(eth_key, hash_in_hex)
        if eip_1559_identifier:
            v = int(v_raw)
        else:
            v = signing.to_eth_v(int(v_raw), chain_id)

        r = int(r_raw)
        s = int(s_raw)
        return (v, r, s)
