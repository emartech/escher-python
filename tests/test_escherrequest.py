import unittest

from escherauth.escherauth import EscherRequest


class EscherRequestTest(unittest.TestCase):
    def test_object_basic(self):
        request = EscherRequest({
            'method': 'GET',
            'host': 'host.foo.com',
            'url': '/?foo=bar',
            'headers': [
                ('Date', 'Mon, 09 Sep 2011 23:36:00 GMT'),
                ('Host', 'host.foo.com'),
            ],
        })
        self.assertEqual(request.method(), 'GET')
        self.assertEqual(request.host(), 'host.foo.com')
        self.assertEqual(request.path(), '/')
        self.assertListEqual(request.query_parts(), [
            ('foo', 'bar'),
        ])
        self.assertListEqual(request.headers(), [
            ('Date', 'Mon, 09 Sep 2011 23:36:00 GMT'),
            ('Host', 'host.foo.com'),
        ])
        self.assertEqual(request.body(), None)  # there was no body specified

    def test_object_complex(self):
        request = EscherRequest({
            'method': 'POST',
            'host': 'host.foo.com',
            'url': '/example/path/?foo=bar&abc=cba',
            'headers': [],
            'body': 'HELLO WORLD!',
        })
        self.assertEqual(request.method(), 'POST')
        self.assertEqual(request.host(), 'host.foo.com')
        self.assertEqual(request.path(), '/example/path/')
        self.assertListEqual(request.query_parts(), [
            ('foo', 'bar'),
            ('abc', 'cba'),
        ])
        self.assertListEqual(request.headers(), [])
        self.assertEqual(request.body(), 'HELLO WORLD!')

    def test_object_add_header(self):
        request = EscherRequest({
            'method': 'POST',
            'host': 'host.foo.com',
            'url': '/example/path/?foo=bar&abc=cba',
            'headers': [],
            'body': 'HELLO WORLD!',
        })
        request.add_header('Foo', 'Bar')
        self.assertListEqual(request.headers(), [['Foo', 'Bar']])
