import mock
import pytest
import requests
import urllib3

from sgx.http import send_request
from sgx.http import SgxUnreachableError

URL = 'http://127.0.0.1:1026'
INVALID_URL = 'http://127.0.0.1:1033'

TEST_MAX_RETRIES = 5
MIN_TIME_DELTA = 15


def test_send_request_failed_sgx_down():
    method = 'POST'
    params = {'data': 'test'}
    with pytest.raises(SgxUnreachableError):
        send_request(INVALID_URL, method, params)


def test_send_request_failed_sgx_up():
    method = 'POST'
    params = {'data': 'test'}

    def post_mock(*args, **kwargs):
        err = requests.exceptions.ConnectionError('Test')
        err.args = (urllib3.exceptions.MaxRetryError(URL, 'test'),)
        raise err

    with mock.patch('requests.post', post_mock):
        with pytest.raises(SgxUnreachableError):
            send_request(URL, method, params)
