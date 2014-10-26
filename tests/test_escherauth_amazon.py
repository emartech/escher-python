import unittest
import datetime

from escherauth.escherauth import Escher
from nose_parameterized import parameterized


def read_request(suite, test, extension='req'):
    file = open('tests/' + suite + '_testsuite/' + test + '.' + extension, 'r')
    lines = (file.read() + "\n").splitlines()
    file.close()

    method, uri = lines[0].split(' ')[0:2]
    headers = []
    for header in lines[1:-2]:
        key, value = header.split(':', 1)
        headers.append((key, value.lstrip()))
    body = lines[-1]

    return {
        'method': method,
        'host': 'host.foo.com',
        'uri': uri,
        'headers': headers,
        'body': body,
    }


class EscherAuthAmazonTest(unittest.TestCase):
    def setUp(self):
        self.escher = Escher('us-east-1/host/aws4_request', {
            'algo_prefix': 'AWS4',
            'vendor_key': 'AWS4',
            'hash_algo': 'SHA256',
            'auth_header_name': 'Authorization',
            'date_header_name': 'Date',
            'current_time': datetime.datetime(2011, 9, 9, 23, 36)
        })

    @parameterized.expand([
        ('get-header-value-trim'),
        ('get-relative'),
        ('get-relative-relative'),
        ('get-slash'),
        ('get-slash-dot-slash'),
        ('get-slash-pointless-dot'),
        ('get-slashes'),
        ('get-space'),
        ('get-unreserved'),
        ('get-utf8'),
        ('get-vanilla'),
        ('get-vanilla-empty-query-key'),
        ('get-vanilla-query'),
        ('get-vanilla-query-order-key'),
        ('get-vanilla-query-order-key-case'),
        ('get-vanilla-query-order-value'),
        ('get-vanilla-query-unreserved'),
        ('get-vanilla-ut8-query'),
        ('post-header-key-case'),
        ('post-header-key-sort'),
        ('post-header-value-case'),
        ('post-vanilla'),
        ('post-vanilla-empty-query-value'),
        ('post-vanilla-query'),
        ('post-vanilla-query-nonunreserved'),
        ('post-vanilla-query-space'),
        ('post-x-www-form-urlencoded'),
        ('post-x-www-form-urlencoded-parameters'),
    ])
    def test_signing(self, testcase):
        suite = 'aws4'
        request = read_request(suite, testcase)
        request_signed = read_request(suite, testcase, 'sreq')
        headers_to_sign = [header[0].lower() for header in request['headers']]
        request = self.escher.sign(request, {
            'api_key': 'AKIDEXAMPLE',
            'api_secret': 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY'
        }, headers_to_sign)
        self.assertEqual(request.get('method'), request_signed.get('method'))
        self.assertEqual(request.get('host'), request_signed.get('host'))
        self.assertEqual(request.get('uri'), request_signed.get('uri'))
        self.assertListEqual(request.get('headers'), request_signed.get('headers'))
        self.assertEqual(request.get('body'), request_signed.get('body'))
