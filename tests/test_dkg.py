from sgx import SgxClient
import os
from time import sleep


def convert_g2_point_to_hex(data):
    data_hexed = ""
    for coord in data:
        temp = hex(int(coord))[2:]
        while (len(temp) < 64):
            temp = '0' + temp
        data_hexed += temp
    return data_hexed


t = int(os.environ['t'])
n = int(os.environ['n'])

sgx = SgxClient(os.environ['SERVER'])

public_keys = []
key_name = []

for i in range(n):
    generated_key = sgx.generate_key()
    public_keys.append(generated_key.public_key)
    key_name.append(generated_key.key_name)
    sleep(1)

for i in range(n):
    poly_name = "POLY:SCHAIN_ID:" + str(0) + ":NODE_ID:" + str(i) + ":DKG_ID:" + str(0)
    response = sgx.generate_dkg_poly(poly_name)
    if not response:
        raise TypeError("failed generate dkg poly for " + str(i))
    sleep(1)

verification_vector = []
for i in range(n):
    verification_vector.append(sgx.get_verification_vector("poly" + str(i), n, t))
    sleep(1)

hexed_vv = []

for vv in verification_vector:
    cur_hexed = ""
    for elem in vv:
        cur_hexed += convert_g2_point_to_hex(elem)
    hexed_vv.append(cur_hexed)

secret_key_contribution = []
for i in range(n):
    secret_key_contribution.append(
        sgx.get_secret_key_contribution("poly" + str(i), public_keys, n, t))
    sleep(1)

for i in range(n):
    for j in range(n):
        if not sgx.verify_secret_share(
                hexed_vv[j],
                key_name[i],
                secret_key_contribution[j][192*i:192*(i + 1)], n, t, i):
            raise ValueError("failed to verify")
        sleep(1)

for i in range(n):
    sgx.create_bls_private_key(
        "poly" + str(i),
        "key" + str(i + 100),
        key_name[i],
        "".join(secret_key_contribution[j][192*i:192*(i + 1)] for j in range(n)), n, t)
    sleep(1)
