import json
import re
import unittest
import datetime
from pathlib import Path

from escherauth.escherauth import Escher, EscherException
from nose2.tools import params


class TestCase:
    FILE_PATTERN = re.compile(r'^test-cases/([^/]+)/([^-]+)-([^.]+).json$')

    @staticmethod
    def get_case_files(type):
        cases = []
        for f in Path('test-cases/').glob('**/*.json'):
            if not f.is_file():
                continue

            case = TestCase(f)
            if case.type != type:
                continue
            if case.suite == '.conflict':
                continue

            cases.append(case)
        return cases

    def __init__(self, case_file: Path):
        (self.suite, self.type, self.name) = self.FILE_PATTERN.match(str(case_file)).groups()
        with open(case_file, 'r') as f:
            self.__data = json.load(f)

    @property
    def credential_scope(self):
        return self.__data['config']['credentialScope']

    @property
    def headers_to_sign(self):
        return self.__data['headersToSign']

    @property
    def request(self):
        return self.__data['request']

    @property
    def expected(self):
        return self.__data['expected']

    @property
    def mandatory_signed_headers(self):
        return self.__data.get('mandatorySignedHeaders')

    @property
    def sign_options(self):
        return {
            'algo_prefix': self.__data['config'].get('algoPrefix'),
            'vendor_key': self.__data['config'].get('vendorKey'),
            'hash_algo': self.__data['config'].get('hashAlgo'),
            'auth_header_name': self.__data['config'].get('authHeaderName'),
            'date_header_name': self.__data['config'].get('dateHeaderName'),
            'current_time': self.__get_current_time(),
        }

    @property
    def authenticate_options(self):
        return {
            'algo_prefix': self.__data['config'].get('algoPrefix'),
            'vendor_key': self.__data['config'].get('vendorKey'),
            'auth_header_name': self.__data['config'].get('authHeaderName'),
            'date_header_name': self.__data['config'].get('dateHeaderName'),
            'current_time': self.__get_current_time(),
        }

    @property
    def api_key(self):
        return self.__data['config'].get('accessKeyId')

    @property
    def api_secret(self):
        return self.__data['config'].get('apiSecret')

    @property
    def key_db(self):
        return dict(self.__data['keyDb'])

    def __repr__(self):
        return f'{self.suite}/{self.type}-{self.name}.json'

    def __get_current_time(self):
        time_formats = ['%Y-%m-%dT%H:%M:%S.000Z', '%Y-%m-%dT%H:%M:%SZ', '%a, %d %b %Y %H:%M:%S GMT']

        current_time = None
        for format in time_formats:
            try:
                current_time = datetime.datetime.strptime(self.__data['config']['date'], format).replace(tzinfo=datetime.timezone.utc)
            except ValueError:
                pass

        if current_time is None:
            raise Exception(f"Invalid time: {self.__data['config']['date']}")

        return current_time


class EscherAuthEndToEndTest(unittest.TestCase):

    def setUp(self) -> None:
        self.maxDiff = None

    @params(*TestCase.get_case_files('signrequest'))
    def test_sign_request(self, test_case: TestCase):
        escher = Escher(test_case.api_key, test_case.api_secret, test_case.credential_scope, test_case.sign_options)

        try:
            request = escher.sign_request(test_case.request, test_case.headers_to_sign)
            if 'request' in test_case.expected:
                self.assertEqual(request, test_case.expected['request'])
            else:
                raise Exception('no request in expected')
        except EscherException as e:
            if 'error' in test_case.expected:
                self.assertEqual(str(e), test_case.expected['error'])
            else:
                raise e

    @params(*TestCase.get_case_files('authenticate'))
    def test_authenticate(self, test_case: TestCase):
        escher = Escher(test_case.api_key, test_case.api_secret, test_case.credential_scope, test_case.authenticate_options)

        try:
            api_key = escher.authenticate(test_case.request, test_case.key_db, test_case.mandatory_signed_headers)
            if 'apiKey' in test_case.expected:
                self.assertEqual(api_key, test_case.expected['apiKey'])
            else:
                raise Exception('no apiKey in expected')
        except EscherException as e:
            if 'error' in test_case.expected:
                self.assertEqual(str(e), test_case.expected['error'])
            else:
                raise e

    @params(*TestCase.get_case_files('presignurl'))
    def test_presign_url(self, test_case: TestCase):
        escher = Escher(test_case.api_key, test_case.api_secret, test_case.credential_scope, test_case.sign_options)
        url = escher.presign_url(test_case.request['url'], test_case.request['expires'])

        self.assertEqual(url, test_case.expected['url'])
