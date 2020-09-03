from sgx.utils import request_keyname_to_sha3


def test_request_keyname_to_sha3():
    request = {'id': 0, 'jsonrpc': '2.0', 'method': 'getPublicECDSAKey',
               'params': {'keyName': 'NEK:3ea52b17bf12f666fa7df713'}}
    res = request_keyname_to_sha3(request)
    assert res == {'id': 0, 'jsonrpc': '2.0', 'method': 'getPublicECDSAKey', 'params': {'keyNameHash': '62d71350041906820c078ab24e5b0ae65fad082dcc3068eb2296ee021939c03a'}}  # noqa
