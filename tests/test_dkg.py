from sgx import SgxClient
from sgx.sgx_rpc_handler import DkgPolyStatus, SgxServerError
import os
from time import sleep
from dotenv import load_dotenv
import random
import coincurve
import binascii
import pytest

load_dotenv()


def bxor(b1, b2):
    parts = []
    for b1, b2 in zip(b1, b2):
        parts.append(bytes([b1 ^ b2]))
    return b''.join(parts)


def decrypt(ciphertext, secret_key):
    xor_val = bxor(ciphertext, secret_key)
    ret_val = binascii.hexlify(xor_val)
    return str(int(ret_val.decode(), 16))


def convert_g2_point_to_hex(data):
    data_hexed = ""
    for coord in data:
        temp = hex(int(coord))[2:]
        while (len(temp) < 64):
            temp = '0' + temp
        data_hexed += temp
    return data_hexed


def perform_complaint(sgx, poly_name, public_key, corrupted_secret_key_contribution):
    response = sgx.complaint_response(poly_name, 1)
    share, dh_key = response["share"], response["dh_key"]
    ecdh_key = coincurve.PublicKey(bytes.fromhex("04" + public_key[2:])).multiply(
                coincurve.keys.PrivateKey.from_hex(dh_key).secret).format(compressed=False)[1:33]
    decrypted_key = decrypt(bytes.fromhex(corrupted_secret_key_contribution), ecdh_key)
    mult_g2 = sgx.mult_g2(decrypted_key)
    share = share.split(':')
    assert share == mult_g2


def perform_dkg(t, n, with_0x=True, with_complaint=False):
    sgx = SgxClient(os.environ['SERVER'], path_to_cert=os.environ.get('CERT_PATH'), n=n, t=t)

    public_keys = []
    key_name = []

    random_dkg_id = random.randint(0, 10**50)

    for i in range(n):
        generated_key = sgx.generate_key()
        if with_0x:
            public_keys.append(generated_key.public_key)
        else:
            public_keys.append(generated_key.public_key[2:])
        key_name.append(generated_key.name)
        sleep(1)

    for i in range(n):
        poly_name = (
            "POLY:SCHAIN_ID:"
            f"{str(0)}"
            ":NODE_ID:"
            f"{str(i)}"
            ":DKG_ID:"
            f"{str(random_dkg_id)}"
        )
        response = sgx.generate_dkg_poly(poly_name)
        if response == DkgPolyStatus.FAIL:
            raise TypeError("failed generate dkg poly for " + str(i))
        sleep(1)

    verification_vector = []
    for i in range(n):
        poly_name = (
            "POLY:SCHAIN_ID:"
            f"{str(0)}"
            ":NODE_ID:"
            f"{str(i)}"
            ":DKG_ID:"
            f"{str(random_dkg_id)}"
        )
        verification_vector.append(sgx.get_verification_vector(poly_name))
        sleep(1)

    hexed_vv = []

    for vv in verification_vector:
        cur_hexed = ""
        for elem in vv:
            cur_hexed += convert_g2_point_to_hex(elem)
        hexed_vv.append(cur_hexed)

    secret_key_contribution = []
    for i in range(n):
        poly_name = (
            "POLY:SCHAIN_ID:"
            f"{str(0)}"
            ":NODE_ID:"
            f"{str(i)}"
            ":DKG_ID:"
            f"{str(random_dkg_id)}"
        )
        secret_key_contribution.append(
            sgx.get_secret_key_contribution(poly_name, public_keys))
        sleep(1)

    if not with_complaint:
        for i in range(n):
            for j in range(n):
                if not sgx.verify_secret_share(
                        hexed_vv[j],
                        key_name[i],
                        secret_key_contribution[j][192*i:192*(i + 1)], i):
                    raise ValueError("failed to verify")
                sleep(1)

        for i in range(n):
            poly_name = (
                "POLY:SCHAIN_ID:"
                f"{str(0)}"
                ":NODE_ID:"
                f"{str(i)}"
                ":DKG_ID:"
                f"{str(random_dkg_id)}"
            )
            bls_key_name = (
                "BLS_KEY:SCHAIN_ID:"
                f"{str(0)}"
                ":NODE_ID:"
                f"{str(i)}"
                ":DKG_ID:"
                f"{str(random_dkg_id)}"
            )
            sgx.create_bls_private_key(
                poly_name,
                bls_key_name,
                key_name[i],
                "".join(secret_key_contribution[j][192*i:192*(i + 1)] for j in range(n)))

            sgx.get_bls_public_key(bls_key_name)
            sgx.delete_bls_key(bls_key_name)

            try:
                sgx.delete_bls_key(bls_key_name)
            except SgxServerError as e:
                assert str(e) == f'BLS key with such name not found: {bls_key_name}'
            sleep(1)
    else:
        corrupted_secret_key_contribution = secret_key_contribution[0]
        secret_key_contribution[0] = secret_key_contribution[1]

        for i in range(n):
            for j in range(n):
                if j == 0:
                    assert not sgx.verify_secret_share(
                            hexed_vv[j],
                            key_name[i],
                            secret_key_contribution[j][192*i:192*(i + 1)], i)
                else:
                    assert sgx.verify_secret_share(
                            hexed_vv[j],
                            key_name[i],
                            secret_key_contribution[j][192*i:192*(i + 1)], i)
                sleep(1)

        poly_name = (
                "POLY:SCHAIN_ID:"
                f"{str(0)}"
                ":NODE_ID:"
                f"{str(0)}"
                ":DKG_ID:"
                f"{str(random_dkg_id)}"
            )
        perform_complaint(
                        sgx,
                        poly_name,
                        public_keys[1],
                        corrupted_secret_key_contribution[192:256]
                        )


def test_dkg():
    perform_dkg(2, 2, with_0x=True)
    print("TEST WITH 0x PREFIX PASSED")
    perform_dkg(2, 2, with_0x=False)
    print("TEST WITHOUT 0x PREFIX PASSED")


def test_dkg_complaint():
    perform_dkg(2, 2, with_complaint=True)
    print("TEST DKG COMPLAINT PASSED")


@pytest.mark.longtest
def test_dkg_random():
    for i in range(10):
        n = random.randint(2, 16)
        t = random.randint(2, n)
        print("TESTING DKG RANDOM")
        print("N:", n)
        print("T:", t)

        perform_dkg(t, n)
        print("TEST SUCCESSFULLY PASSED")
    print("TEST DKG RANDOM PASSED")


def test_poly_existance():
    sgx = SgxClient(os.environ['SERVER'], path_to_cert=os.environ.get('CERT_PATH'), n=2, t=2)

    random_dkg_id = random.randint(0, 10**50)

    poly_name = (
            "POLY:SCHAIN_ID:"
            f"{str(0)}"
            ":NODE_ID:"
            f"{str(0)}"
            ":DKG_ID:"
            f"{str(random_dkg_id)}"
        )
    assert sgx.generate_dkg_poly(poly_name) == DkgPolyStatus.NEW_GENERATED
    assert sgx.is_poly_exists(poly_name)
    poly_name_incorrect = (
            "POLY:SCHAIN_ID:"
            f"{str(0)}"
            ":NODE_ID:"
            f"{str(0)}"
            ":DKG_ID:"
            f"{str(random_dkg_id+1)}"
        )
    assert not sgx.is_poly_exists(poly_name_incorrect)
    response = sgx.generate_dkg_poly(poly_name)
    assert response == DkgPolyStatus.PREEXISTING
    print("TEST POLY EXISTANCE PASSED")


def test_import():
    sgx = SgxClient(os.environ['SERVER'], path_to_cert=os.environ.get('CERT_PATH'), n=2, t=2)

    random_dkg_id = random.randint(0, 10**50)

    bls_key_name = (
                "BLS_KEY:SCHAIN_ID:"
                f"{str(0)}"
                ":NODE_ID:"
                f"{str(0)}"
                ":DKG_ID:"
                f"{str(random_dkg_id)}"
    )

    insecure_bls_private_key = "f253bad7b1f62b8ff60bbf451cf2e8e9ebb5d6e9bff450c55b8d5504b8c63d3"

    response = sgx.import_bls_private_key(bls_key_name, 1, insecure_bls_private_key)

    assert len(response) > 0
    print("TEST IMPORT BLS KEY PASSED")
