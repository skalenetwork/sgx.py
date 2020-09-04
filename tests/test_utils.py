from sgx.utils import request_keyname_to_sha3


def test_request_keyname_to_sha3():
    request = {'id': 0, 'jsonrpc': '2.0', 'method': 'getPublicECDSAKey',
               'params': {'keyName': 'NEK:3ea52b17bf12f666fa7df713'}}
    res = request_keyname_to_sha3(request)
    assert res == {'id': 0, 'jsonrpc': '2.0', 'method': 'getPublicECDSAKey', 'params': {'keyNameHash': 'a56cb859349fb9a23f60b75cf28adcf15c04134667c3577c423976c613187b47'}}  # noqa
