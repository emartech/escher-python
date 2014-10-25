import unittest
import datetime

from escherauth import Escher


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

    def test_signing(self):
        request = {
            'method': 'GET',
            'host': 'host.foo.com',
            'uri': '/?foo=bar',
            'headers': [
                ('Date', 'Mon, 09 Sep 2011 23:36:00 GMT'),
                ('Host', 'host.foo.com'),
            ],
        }
        request = self.escher.sign(request, {
            'api_key': 'AKIDEXAMPLE',
            'api_secret': 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY'
        })
        self.assertEqual(request.get('method'), 'GET')
        self.assertEqual(request.get('host'), 'host.foo.com')
        self.assertEqual(request.get('uri'), '/?foo=bar')
        self.assertListEqual(request.get('headers'), [
            ('Date', 'Mon, 09 Sep 2011 23:36:00 GMT'),
            ('Host', 'host.foo.com'),
            ('Authorization', 'AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE, SignedHeaders=date;host, Signature=56c054473fd260c13e4e7393eb203662195f5d4a1fada5314b8b52b23f985e9f')
        ])
        self.assertEqual(request.get('body'), None)

