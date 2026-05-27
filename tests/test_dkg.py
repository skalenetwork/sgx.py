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

DKG_TEST_SLEEP_SECONDS = float(os.getenv('DKG_TEST_SLEEP_SECONDS', '0.1'))


def dkg_sleep():
    if DKG_TEST_SLEEP_SECONDS > 0:
        sleep(DKG_TEST_SLEEP_SECONDS)


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


def get_sgx_client(n, t, with_zmq=False):
    if not with_zmq:
        return SgxClient(os.environ['SERVER'], path_to_cert=os.environ.get('CERT_PATH'), n=n, t=t)
    return SgxClient(
        os.environ['SERVER'], path_to_cert=os.environ.get('CERT_PATH'), n=n, t=t, zmq=True
    ).zmq


def get_poly_name(node_id, dkg_id):
    return (
        "POLY:SCHAIN_ID:"
        f"{str(0)}"
        ":NODE_ID:"
        f"{str(node_id)}"
        ":DKG_ID:"
        f"{str(dkg_id)}"
    )


def get_bls_key_name(node_id, dkg_id):
    return (
        "BLS_KEY:SCHAIN_ID:"
        f"{str(0)}"
        ":NODE_ID:"
        f"{str(node_id)}"
        ":DKG_ID:"
        f"{str(dkg_id)}"
    )


def hex_verification_vectors(verification_vectors):
    hexed_vv = []
    for vv in verification_vectors:
        cur_hexed = ""
        for elem in vv:
            cur_hexed += convert_g2_point_to_hex(elem)
        hexed_vv.append(cur_hexed)
    return hexed_vv


def assert_bls_signature(sgx, bls_key_name):
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


def assert_new_dkg_poly(response, node_id):
    if response.name == 'FAIL':
        raise TypeError("failed generate dkg poly for " + str(node_id))
    assert response.name == 'NEW_GENERATED'


def perform_dkg_v3(t=3, n=4, with_zmq=False):
    initial_dkg = perform_dkg(t, n, with_0x=True, with_v2=not with_zmq, with_zmq=with_zmq)
    sgx = initial_dkg['sgx']

    active_node_ids = [0, 1, 2]
    joining_node_id = 3
    new_node_key = sgx.generate_key()

    public_keys = [
        initial_dkg['public_keys'][0],
        initial_dkg['public_keys'][1],
        initial_dkg['public_keys'][2],
        new_node_key.public_key,
    ]
    key_names = [
        initial_dkg['key_names'][0],
        initial_dkg['key_names'][1],
        initial_dkg['key_names'][2],
        new_node_key.name,
    ]
    dkg_sleep()

    random_dkg_id = random.randint(0, 10**50)

    active_poly_names = []
    for node_id in active_node_ids:
        poly_name = get_poly_name(node_id, random_dkg_id)
        response = sgx.generate_dkg_poly_v3(poly_name, initial_dkg['bls_key_names'][node_id])
        assert_new_dkg_poly(response, node_id)
        active_poly_names.append(poly_name)
        dkg_sleep()

    verification_vectors = []
    for poly_name in active_poly_names:
        verification_vectors.append(sgx.get_verification_vector(poly_name))
        dkg_sleep()

    hexed_vv = hex_verification_vectors(verification_vectors)

    secret_key_contributions = []
    for poly_name in active_poly_names:
        if with_zmq:
            secret_key_contributions.append(sgx.get_secret_key_contribution(poly_name, public_keys))
        else:
            secret_key_contributions.append(
                sgx.get_secret_key_contribution_v2(poly_name, public_keys)
            )
        dkg_sleep()

    for i in range(n):
        for j in range(len(active_node_ids)):
            if with_zmq:
                assert sgx.verify_secret_share(
                    hexed_vv[j],
                    key_names[i],
                    secret_key_contributions[j][192*i:192*(i + 1)],
                    i,
                )
            else:
                assert sgx.verify_secret_share_v2(
                    hexed_vv[j],
                    key_names[i],
                    secret_key_contributions[j][192*i:192*(i + 1)],
                    i,
                )
            dkg_sleep()

    for i in range(n):
        poly_name = active_poly_names[i] if i in active_node_ids else None
        if i == joining_node_id:
            assert poly_name is None
        bls_key_name = get_bls_key_name(i, random_dkg_id)
        assert sgx.create_bls_private_key_v3(
            poly_name,
            bls_key_name,
            key_names[i],
            [
                {
                    'contributorIndex': active_node_ids[j],
                    'secretShare': secret_key_contributions[j][192*i:192*(i + 1)],
                }
                for j in range(len(active_node_ids))
            ],
        )

        public_key = sgx.get_bls_public_key(bls_key_name)
        assert len(public_key) == 4
        assert all(len(point) > 0 for point in public_key)
        assert_bls_signature(sgx, bls_key_name)
        dkg_sleep()


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
    sgx = get_sgx_client(n, t, with_zmq=with_zmq)

    public_keys = []
    generated_public_keys = []
    key_name = []

    random_dkg_id = random.randint(0, 10**50)

    for i in range(n):
        generated_key = sgx.generate_key()
        if with_0x:
            public_keys.append(generated_key.public_key)
        else:
            public_keys.append(generated_key.public_key[2:])
        generated_public_keys.append(generated_key.public_key)
        key_name.append(generated_key.name)
        dkg_sleep()

    for i in range(n):
        poly_name = get_poly_name(i, random_dkg_id)
        response = sgx.generate_dkg_poly(poly_name)
        assert_new_dkg_poly(response, i)
        dkg_sleep()

    verification_vector = []
    for i in range(n):
        poly_name = get_poly_name(i, random_dkg_id)
        verification_vector.append(sgx.get_verification_vector(poly_name))
        dkg_sleep()

    hexed_vv = hex_verification_vectors(verification_vector)

    secret_key_contribution = []
    for i in range(n):
        poly_name = get_poly_name(i, random_dkg_id)

        if with_v2:
            secret_key_contribution.append(
                sgx.get_secret_key_contribution_v2(poly_name, public_keys))
        else:
            print("KEYS", public_keys)
            secret_key_contribution.append(
                sgx.get_secret_key_contribution(poly_name, public_keys))
        dkg_sleep()

    if not with_complaint:
        for i in range(n):
            for j in range(n):
                if with_v2:
                    if not sgx.verify_secret_share_v2(
                            hexed_vv[j],
                            key_name[i],
                            secret_key_contribution[j][192*i:192*(i + 1)], i):
                        raise ValueError(f'{i} failed to verify {j}')
                    dkg_sleep()
                else:
                    if not sgx.verify_secret_share(
                            hexed_vv[j],
                            key_name[i],
                            secret_key_contribution[j][192*i:192*(i + 1)], i):
                        raise ValueError(f'{i} failed to verify {j}')
                    dkg_sleep()

        calculated_bls_public_keys = sgx.calculate_all_bls_public_keys(hexed_vv)
        bls_key_names = []

        for i in range(n):
            poly_name = get_poly_name(i, random_dkg_id)
            bls_key_name = get_bls_key_name(i, random_dkg_id)

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
            bls_key_names.append(bls_key_name)

            public_key = sgx.get_bls_public_key(bls_key_name)

            assert ":".join(public_key) == calculated_bls_public_keys[i]

            assert_bls_signature(sgx, bls_key_name)
            dkg_sleep()

        return {
            'sgx': sgx,
            'public_keys': generated_public_keys,
            'key_names': key_name,
            'bls_key_names': bls_key_names,
        }
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
                dkg_sleep()

        poly_name = get_poly_name(0, random_dkg_id)
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


def test_dkg_v3():
    perform_dkg_v3(3, 4)
    perform_dkg_v3(3, 4, with_zmq=True)
    print("TEST DKG V3 PASSED")


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
