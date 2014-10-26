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
        ('aws4', 'get-space'),
        ('aws4', 'get-unreserved'),
        ('aws4', 'get-utf8'),
    ])
    def test_signing(self, suite, testcase):
        request = read_request(suite, testcase)
        request_signed = read_request(suite, testcase, 'sreq')
        request = self.escher.sign(request, {
            'api_key': 'AKIDEXAMPLE',
            'api_secret': 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY'
        })
        self.assertEqual(request.get('method'), request_signed.get('method'))
        self.assertEqual(request.get('host'), request_signed.get('host'))
        self.assertEqual(request.get('uri'), request_signed.get('uri'))
        self.assertListEqual(request.get('headers'), request_signed.get('headers'))
        self.assertEqual(request.get('body'), request_signed.get('body'))
