import unittest

import datetime

from escherauth.escherauth import Escher, EscherException, AuthParams, AuthenticationValidator


class AuthParamsTest(unittest.TestCase):

    def test_get_throws_exception_if_key_is_not_found(self):
        params = AuthParams.from_query_parts([], 'EMS')
        try:
            params.get('test')
            self.fail('No exception thrown')
        except EscherException as e:
            self.assertEqual('Missing authorization parameter: test', str(e))

    def test_get_signed_headers(self):
        params = AuthParams.from_query_parts([('X-EMS-SignedHeaders', 'host;date')], 'EMS')
        self.assertEqual(['host', 'date'], params.get_signed_headers())

    def test_get_algo_data(self):
        params = AuthParams.from_query_parts([('X-EMS-Algorithm', 'EMS-HMAC-SHA256')], 'EMS')
        self.assertEqual(['EMS', 'HMAC', 'SHA256'], params.get_algo_data())

    def test_get_algo_prefix(self):
        params = AuthParams.from_query_parts([('X-EMS-Algorithm', 'EMS-HMAC-SHA256')], 'EMS')
        self.assertEqual('EMS', params.get_algo_prefix())

    def test_get_hash_algo(self):
        params = AuthParams.from_query_parts([('X-EMS-Algorithm', 'EMS-HMAC-SHA256')], 'EMS')
        self.assertEqual('SHA256', params.get_hash_algo())

    def test_get_credential_data(self):
        params = AuthParams.from_query_parts([('X-EMS-Credentials', 'th3K3y/20110511/us-east-1/host/aws4_request')], 'EMS')
        self.assertEqual(['th3K3y', '20110511', 'us-east-1/host/aws4_request'], params.get_credential_data())

    def test_get_credential_key(self):
        params = AuthParams.from_query_parts([('X-EMS-Credentials', 'th3K3y/20110511/us-east-1/host/aws4_request')], 'EMS')
        self.assertEqual('th3K3y', params.get_credential_key())

    def test_get_credential_date(self):
        params = AuthParams.from_query_parts([('X-EMS-Credentials', 'th3K3y/20110511/us-east-1/host/aws4_request')], 'EMS')
        self.assertEqual(datetime.datetime(2011, 5, 11, 0, 0, tzinfo=datetime.timezone.utc), params.get_credential_date())

    def test_get_credential_scope(self):
        params = AuthParams.from_query_parts([('X-EMS-Credentials', 'th3K3y/20110511/us-east-1/host/aws4_request')], 'EMS')
        self.assertEqual('us-east-1/host/aws4_request', params.get_credential_scope())

    def test_get_expires(self):
        params = AuthParams.from_query_parts([('X-EMS-Expires', '300')], 'EMS')
        self.assertEqual(300, params.get_expires())

    def test_get_request_date(self):
        params = AuthParams.from_query_parts([('X-EMS-Date', '20110511T120000Z')], 'EMS')
        self.assertEqual(datetime.datetime(2011, 5, 11, 12, 0, tzinfo=datetime.timezone.utc), params.get_request_date())


class AuthenticationValidatorTest(unittest.TestCase):
    def setUp(self):
        self.validator = AuthenticationValidator()

    def test_validate_mandatory_signed_headers(self):
        try:
            self.validator.validate_mandatory_signed_headers(['host'], ['test'])
            self.fail('No exception thrown')
        except EscherException as e:
            self.assertEqual('The host header is not signed', str(e))

    def test_validate_hash_algo(self):
        try:
            self.validator.validate_hash_algo('test')
            self.fail('No exception thrown')
        except EscherException as e:
            self.assertEqual('Only SHA256 and SHA512 hash algorithms are allowed', str(e))

    def test_validate_dates_date_mismatch(self):
        try:
            self.validator.validate_dates(datetime.datetime(2011, 5, 11, 12, 0, tzinfo=datetime.timezone.utc), datetime.datetime(2011, 5, 11, 12, 0, tzinfo=datetime.timezone.utc), datetime.datetime(2011, 5, 10, 0, 0, tzinfo=datetime.timezone.utc), 60, 300)
            self.fail('No exception thrown')
        except EscherException as e:
            self.assertEqual('The credential date does not match with the request date', str(e))

    def test_validate_dates_date_out_of_range(self):
        try:
            self.validator.validate_dates(datetime.datetime(2011, 5, 11, 12, 10, tzinfo=datetime.timezone.utc), datetime.datetime(2011, 5, 11, 12, 0, tzinfo=datetime.timezone.utc), datetime.datetime(2011, 5, 11, 0, 0, tzinfo=datetime.timezone.utc), 60, 300)
            self.fail('No exception thrown')
        except EscherException as e:
            self.assertEqual('The request date is not within the accepted time range', str(e))

    def test_validate_credential_scope(self):
        try:
            self.validator.validate_credential_scope('a', 'b')
            self.fail('No exception thrown')
        except EscherException as e:
            self.assertEqual('The credential scope is invalid', str(e))

    def test_validate_signature(self):
        try:
            self.validator.validate_signature('a', 'b')
            self.fail('No exception thrown')
        except EscherException as e:
            self.assertEqual('The signatures do not match', str(e))


class AuthenticateTest(unittest.TestCase):
    def setUp(self):
        self.credential_scope = 'us-east-1/host/aws4_request'
        self.key_db = {'th3K3y': 'very_secure'}

    def test_authenticate_error_presigned_url_expired(self):
        escher = Escher(None, None, self.credential_scope, self.get_options('2011-05-30T12:00:00.000Z'))

        try:
            uri = '/something?foo=bar&baz=barbaz&X-EMS-Algorithm=EMS-HMAC-SHA256&X-EMS-Credentials=th3K3y%2F20110511%2Fus-east-1%2Fhost%2Faws4_request&X-EMS-Date=20110511T120000Z&X-EMS-Expires=123456&X-EMS-SignedHeaders=host&X-EMS-Signature=fbc9dbb91670e84d04ad2ae7505f4f52ab3ff9e192b8233feeae57e9022c2b67'
            escher.authenticate(self.get_request(uri), self.key_db)
            self.fail('No exception thrown')
        except EscherException as e:
            self.assertEqual('The request date is not within the accepted time range', str(e))

    def test_authenticate_error_presigned_url_invalid_escher_key(self):
        escher = Escher(None, None, self.credential_scope, self.get_options('2011-05-11T12:00:00.000Z'))

        try:
            uri = '/something?foo=bar&baz=barbaz&X-EMS-Algorithm=EMS-HMAC-SHA256&X-EMS-Credentials=INVALID%2F20110511%2Fus-east-1%2Fhost%2Faws4_request&X-EMS-Date=20110511T120000Z&X-EMS-Expires=123456&X-EMS-SignedHeaders=host&X-EMS-Signature=fbc9dbb91670e84d04ad2ae7505f4f52ab3ff9e192b8233feeae57e9022c2b67'
            escher.authenticate(self.get_request(uri), self.key_db)
            self.fail('No exception thrown')
        except EscherException as e:
            self.assertEqual('Invalid Escher key', str(e))

    def test_authenticate_valid_presigned_url_with_query(self):
        escher = Escher(None, None, self.credential_scope, self.get_options('2011-05-11T12:00:00.000Z'))

        uri = '/something?foo=bar&baz=barbaz&X-EMS-Algorithm=EMS-HMAC-SHA256&X-EMS-Credentials=th3K3y%2F20110511%2Fus-east-1%2Fhost%2Faws4_request&X-EMS-Date=20110511T120000Z&X-EMS-Expires=123456&X-EMS-SignedHeaders=host&X-EMS-Signature=fbc9dbb91670e84d04ad2ae7505f4f52ab3ff9e192b8233feeae57e9022c2b67'
        result = escher.authenticate(self.get_request(uri), self.key_db)

        self.assertEqual('th3K3y', result)

    def get_options(self, current_time):
        return {
            'vendor_key': 'EMS',
            'algo_prefix': 'EMS',
            'hash_algo': 'SHA256',
            'current_time': datetime.datetime.strptime(current_time, '%Y-%m-%dT%H:%M:%S.%fZ').replace(tzinfo=datetime.timezone.utc)
        }

    def get_request(self, uri):
        return {
            'method': 'GET',
            'url': uri,
            'headers': [
                ['Host', 'example.com']
            ],
            'body': 'UNSIGNED-PAYLOAD'
        }
