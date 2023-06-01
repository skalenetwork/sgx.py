from sgx import SgxClient
from sgx.sgx_rpc_handler import SgxServerError
from sgx.sgx_zmq import SgxZmqServerError
import os
from time import sleep
from dotenv import load_dotenv
import random
import coincurve
import binascii
import secrets
import hashlib

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


def perform_complaint(sgx, t, poly_name, public_key, corrupted_secret_key_contribution):
    response = sgx.complaint_response(poly_name, 1)
    share, dh_key = response.share, response.dh_key

    ecdh_key, _ = (coincurve.PublicKey(bytes.fromhex("04" + public_key[2:])).multiply(
                coincurve.keys.PrivateKey.from_hex(dh_key).secret)).point()
    ecdh_key = hex(ecdh_key)[2:]
    while len(ecdh_key) < 64:
        ecdh_key = '0' + ecdh_key

    derived_key = hashlib.sha256(bytes.fromhex(ecdh_key)).digest()

    decrypted_key = decrypt(bytes.fromhex(corrupted_secret_key_contribution), derived_key)

    mult_g2 = sgx.mult_g2(decrypted_key)
    share = share.split(':')
    assert share == mult_g2

    verification_vector_mult = response.verification_vector_mult
    assert len(verification_vector_mult) == t


def perform_dkg(t, n, with_0x=True, with_v2=True, with_complaint=False, with_zmq=False):
    sgx = None
    if not with_zmq:
        sgx = SgxClient(os.environ['SERVER'], path_to_cert=os.environ.get('CERT_PATH'), n=n, t=t)
    else:
        sgx = SgxClient(os.environ['SERVER'], path_to_cert=os.environ.get('CERT_PATH'),
                        n=n, t=t, zmq=True).zmq

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
        from sgx.sgx_rpc_handler import DkgPolyStatus
        response = sgx.generate_dkg_poly(poly_name)
        if response == DkgPolyStatus.FAIL:
            raise TypeError("failed generate dkg poly for " + str(i))
        sleep(5)

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
        sleep(5)

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

        if with_v2:
            secret_key_contribution.append(
                sgx.get_secret_key_contribution_v2(poly_name, public_keys))
        else:
            print("KEYS", public_keys)
            secret_key_contribution.append(
                sgx.get_secret_key_contribution(poly_name, public_keys))
        sleep(5)

    if not with_complaint:
        for i in range(n):
            for j in range(n):
                if with_v2:
                    if not sgx.verify_secret_share_v2(
                            hexed_vv[j],
                            key_name[i],
                            secret_key_contribution[j][192*i:192*(i + 1)], i):
                        raise ValueError(f'{i} failed to verify {j}')
                    sleep(5)
                else:
                    if not sgx.verify_secret_share(
                            hexed_vv[j],
                            key_name[i],
                            secret_key_contribution[j][192*i:192*(i + 1)], i):
                        raise ValueError(f'{i} failed to verify {j}')
                    sleep(5)

        public_keys = sgx.calculate_all_bls_public_keys(hexed_vv)

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

            if with_v2:
                sgx.create_bls_private_key_v2(
                    poly_name,
                    bls_key_name,
                    key_name[i],
                    "".join(secret_key_contribution[j][192*i:192*(i + 1)] for j in range(n)))
            else:
                sgx.create_bls_private_key(
                    poly_name,
                    bls_key_name,
                    key_name[i],
                    "".join(secret_key_contribution[j][192*i:192*(i + 1)] for j in range(n)))

            public_key = sgx.get_bls_public_key(bls_key_name)

            assert ":".join(public_key) == public_keys[i]

            message = secrets.token_hex(32)

            signature_share = sgx.bls_sign(bls_key_name, message)
            splitted_signature = signature_share.split(':')
            assert len(splitted_signature) == 4

            assert len(splitted_signature[0]) > 0
            assert len(splitted_signature[0]) < 78

            assert len(splitted_signature[1]) > 0
            assert len(splitted_signature[1]) < 78

            assert len(splitted_signature[2]) > 0
            assert len(splitted_signature[2]) < 78

            assert int(splitted_signature[3]) < 1000

            sleep(5)
    else:
        corrupted_secret_key_contribution = secret_key_contribution[0]
        secret_key_contribution[0] = secret_key_contribution[1]

        for i in range(n):
            for j in range(n):
                if j == 0:
                    if with_v2:
                        assert not sgx.verify_secret_share_v2(
                                hexed_vv[j],
                                key_name[i],
                                secret_key_contribution[j][192*i:192*(i + 1)], i)
                    else:
                        assert not sgx.verify_secret_share(
                                hexed_vv[j],
                                key_name[i],
                                secret_key_contribution[j][192*i:192*(i + 1)], i)
                else:
                    if with_v2:
                        assert sgx.verify_secret_share_v2(
                                hexed_vv[j],
                                key_name[i],
                                secret_key_contribution[j][192*i:192*(i + 1)], i)
                    else:
                        assert sgx.verify_secret_share(
                                hexed_vv[j],
                                key_name[i],
                                secret_key_contribution[j][192*i:192*(i + 1)], i)
                sleep(5)

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
                        t,
                        poly_name,
                        public_keys[1],
                        corrupted_secret_key_contribution[192:256]
                        )


def perform_poly_existence(with_zmq=False):
    sgx = None
    if not with_zmq:
        print("TESTING SGX WITHOUT ZMQ")
        sgx = SgxClient(os.environ['SERVER'], path_to_cert=os.environ.get('CERT_PATH'), n=2, t=2)
    else:
        print("TESTING SGX WITH ZMQ")
        sgx = SgxClient(os.environ['SERVER'], path_to_cert=os.environ.get('CERT_PATH'),
                        n=2, t=2, zmq=True).zmq

    random_dkg_id = random.randint(0, 10**50)

    poly_name = (
            "POLY:SCHAIN_ID:"
            f"{str(0)}"
            ":NODE_ID:"
            f"{str(0)}"
            ":DKG_ID:"
            f"{str(random_dkg_id)}"
        )
    if with_zmq:
        from sgx.sgx_zmq import DkgPolyStatus
        assert sgx.generate_dkg_poly(poly_name) == DkgPolyStatus.NEW_GENERATED
    else:
        from sgx.sgx_rpc_handler import DkgPolyStatus
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


def perform_import(with_zmq=False, with_0x=False):
    if not with_zmq:
        print("TESTING SGX WITHOUT ZMQ")
        sgx = SgxClient(os.environ['SERVER'], path_to_cert=os.environ.get('CERT_PATH'), n=2, t=2)
    else:
        print("TESTING SGX WITH ZMQ")
        sgx = SgxClient(os.environ['SERVER'], path_to_cert=os.environ.get('CERT_PATH'),
                        n=2, t=2, zmq=True).zmq

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

    response = sgx.import_bls_private_key(bls_key_name, insecure_bls_private_key)

    assert len(response) > 0

    message = secrets.token_hex(32)
    if with_0x:
        message = "0x" + message

    signature_share = sgx.bls_sign(bls_key_name, message)
    splitted_signature = signature_share.split(':')
    assert len(splitted_signature) == 4

    assert len(splitted_signature[0]) > 0
    assert len(splitted_signature[0]) < 78

    assert len(splitted_signature[1]) > 0
    assert len(splitted_signature[1]) < 78

    assert len(splitted_signature[2]) > 0
    assert len(splitted_signature[2]) < 78

    assert int(splitted_signature[3]) < 1000


def perform_delete(with_zmq=False):
    if not with_zmq:
        print("TESTING SGX WITHOUT ZMQ")
        sgx = SgxClient(os.environ['SERVER'], path_to_cert=os.environ.get('CERT_PATH'), n=2, t=2)
    else:
        print("TESTING SGX WITH ZMQ")
        sgx = SgxClient(os.environ['SERVER'], path_to_cert=os.environ.get('CERT_PATH'),
                        n=2, t=2, zmq=True).zmq

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

    response = sgx.import_bls_private_key(bls_key_name, insecure_bls_private_key)

    assert len(response) > 0

    sgx.delete_bls_key(bls_key_name)
    try:
        sgx.delete_bls_key(bls_key_name)
    except SgxServerError as e:
        str_error = f'deleteBlsKeyImpl failed:deleteBlsKeyImpl:BLS key not found: {bls_key_name}'
        assert str(e) == str_error
    except SgxZmqServerError as e:
        str_error = f'deleteBlsKeyImpl failed:deleteBlsKeyImpl:BLS key not found: {bls_key_name}'
        assert str(e) == str_error


def perform_helper(with_zmq=False):
    sgx = None
    if not with_zmq:
        sgx = SgxClient(os.environ['SERVER'], path_to_cert=os.environ.get('CERT_PATH'))
    else:
        sgx = SgxClient(os.environ['SERVER'], path_to_cert=os.environ.get('CERT_PATH'),
                        zmq=True).zmq
    assert sgx.get_server_status() == 0
    assert isinstance(sgx.get_server_version(), str)


def test_dkg():
    perform_dkg(2, 2, with_0x=True)
    print("TEST WITH 0x PREFIX PASSED")
    perform_dkg(2, 2, with_0x=False)
    print("TEST WITHOUT 0x PREFIX PASSED")


def test_old_dkg():
    perform_dkg(2, 2, with_0x=True, with_v2=False)
    print("TEST OLD DKG WITH 0x PREFIX PASSED")
    perform_dkg(2, 2, with_0x=False, with_v2=False)
    print("TEST OLD DKG WITHOUT 0x PREFIX PASSED")


def test_dkg_zmq():
    perform_dkg(2, 2, with_0x=True, with_v2=False, with_zmq=True)
    print("TEST DKG WITH ZMQ PASSED")


def test_dkg_complaint():
    perform_dkg(2, 2, with_complaint=True)
    perform_dkg(2, 2, with_v2=False, with_complaint=True, with_zmq=True)
    print("TEST DKG COMPLAINT PASSED")


def test_poly_existence():
    perform_poly_existence()
    perform_poly_existence(with_zmq=True)
    print("TEST POLY EXISTENCE PASSED")


def test_import():
    perform_import()
    perform_import(with_0x=True)
    perform_import(with_zmq=True)
    perform_import(with_zmq=True, with_0x=True)
    print("TEST IMPORT BLS KEY PASSED")


def test_delete():
    perform_delete()
    perform_delete(with_zmq=True)
    print("TEST DELETE BLS KEY PASSED")


def test_helper_functions():
    perform_helper()
    perform_helper(with_zmq=True)
    print("TEST HELPER FUNCTIONS PASSED")
