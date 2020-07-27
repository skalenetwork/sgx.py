import mock
import requests

from sgx.ssl_utils import send_request

URL = 'http://127.0.0.1:1026'

MAX_RETRIES = 5


def test_send_request_failed():
    method = 'POST'
    params = {'data': 'test'}

    cnt = 0

    def post_mock(*args, **kwargs):
        nonlocal cnt
        if cnt < MAX_RETRIES:
            cnt += 1
            raise requests.exceptions.ConnectionError()
        response_mock = mock.Mock()
        response_mock.json = mock.Mock(return_value={'data': 'test'})
        return response_mock

    with mock.patch('requests.post', post_mock):
        send_request(URL, method, params)
        assert cnt == 5
