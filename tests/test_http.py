from timeit import default_timer as timer

import mock
import requests

from sgx.http import send_request

URL = 'http://127.0.0.1:1026'

TEST_MAX_RETRIES = 5
MIN_TIME_DELTA = 15


def test_send_request_failed():
    method = 'POST'
    params = {'data': 'test'}

    cnt = 0

    def post_mock(*args, **kwargs):
        nonlocal cnt
        if cnt < TEST_MAX_RETRIES:
            cnt += 1
            raise requests.exceptions.ConnectionError()
        response_mock = mock.Mock()
        response_mock.json = mock.Mock(return_value={'data': 'test'})
        return response_mock

    with mock.patch('requests.post', post_mock):
        start_time = timer()
        response = send_request(URL, method, params)
        finish_time = timer()
        assert response == {'data': 'test'}
        assert cnt == 5
        assert finish_time - start_time > MIN_TIME_DELTA
