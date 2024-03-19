import unittest

import requests

from escherauth.escherauth import EscherRequest, EscherException


class EscherRequestTest(unittest.TestCase):
    def test_invalid_http_method(self):
        with self.assertRaisesRegex(EscherException, 'The request method is invalid'):
            EscherRequest({
                'method': 'INVALID',
                'url': '/?foo=bar',
            })

    def test_invalid_path(self):
        with self.assertRaisesRegex(EscherException, 'The request url shouldn\'t contains http or https'):
            EscherRequest({
                'method': 'GET',
                'url': 'http://localhost/?foo=bar',
            })

    def test_no_body(self):
        with self.assertRaisesRegex(EscherException, 'The request body shouldn\'t be empty if the request method is POST'):
            EscherRequest({
                'method': 'POST',
                'url': '/?foo=bar',
            })

    def test_dict_method(self):
        request = EscherRequest({
            'method': 'GET',
            'url': '/?foo=bar',
        })

        self.assertEqual(request.method(), 'GET')

    def test_prepared_request_method(self):
        request = EscherRequest(requests.Request('GET', 'http://localhost/?foo=bar').prepare())

        self.assertEqual(request.method(), 'GET')

    def test_dict_host(self):
        request = EscherRequest({
            'method': 'GET',
            'url': '/?foo=bar',
            'host': 'localhost:8080'
        })

        self.assertEqual(request.host(), 'localhost:8080')

    def test_prepared_request_host(self):
        request = EscherRequest(requests.Request('GET', 'http://localhost:8080/?foo=bar').prepare())

        self.assertEqual(request.host(), 'localhost:8080')

    def test_dict_path(self):
        request = EscherRequest({
            'method': 'GET',
            'url': '/?foo=bar',
        })

        self.assertEqual(request.path(), '/')

    def test_prepared_request_path(self):
        request = EscherRequest(requests.Request('GET', 'http://localhost/?foo=bar').prepare())

        self.assertEqual(request.path(), '/')

    def test_dict_query_parts(self):
        request = EscherRequest({
            'method': 'GET',
            'url': '/?foo=bar',
        })

        self.assertEqual(request.query_parts(), [('foo', 'bar')])

    def test_prepared_request_query_parts(self):
        request = EscherRequest(requests.Request('GET', 'http://localhost/?foo=bar').prepare())

        self.assertEqual(request.query_parts(), [('foo', 'bar')])

    def test_dict_has_query_param(self):
        request = EscherRequest({
            'method': 'GET',
            'url': '/?foo=bar',
        })

        self.assertTrue(request.has_query_param('foo'))
        self.assertFalse(request.has_query_param('bar'))

    def test_prepared_request_has_query_param(self):
        request = EscherRequest(requests.Request('GET', 'http://localhost/?foo=bar').prepare())

        self.assertTrue(request.has_query_param('foo'))
        self.assertFalse(request.has_query_param('bar'))

    def test_dict_headers(self):
        request = EscherRequest({
            'method': 'GET',
            'url': '/?foo=bar',
            'headers': [['Foo', 'bar']],
        })

        self.assertListEqual(request.headers(), [['Foo', 'bar']])

    def test_prepared_request_headers(self):
        request = EscherRequest(requests.Request('GET', 'http://localhost/?foo=bar', headers={'Foo': 'bar'}).prepare())

        self.assertListEqual(request.headers(), [['Foo', 'bar']])

    def test_dict_has_header(self):
        request = EscherRequest({
            'method': 'GET',
            'url': '/?foo=bar',
            'headers': [['Foo', 'bar']],
        })

        self.assertTrue(request.has_header('foo'))
        self.assertFalse(request.has_header('bar'))

    def test_prepared_request_has_header(self):
        request = EscherRequest(requests.Request('GET', 'http://localhost/?foo=bar', headers={'Foo': 'bar'}).prepare())

        self.assertTrue(request.has_header('foo'))
        self.assertFalse(request.has_header('bar'))

    def test_presigned_url_body(self):
        request = EscherRequest({
            'method': 'GET',
            'url': '/?foo=bar',
        })
        request.set_presigned_url(True)

        self.assertEqual(request.body(), 'UNSIGNED-PAYLOAD')

    def test_dict_body(self):
        request = EscherRequest({
            'method': 'POST',
            'url': '/?foo=bar',
            'body': 'foo',
        })

        self.assertEqual(request.body(), 'foo')

    def test_prepared_request_body(self):
        request = EscherRequest(requests.Request('POST', 'http://localhost/?foo=bar', data='foo').prepare())

        self.assertEqual(request.body(), 'foo')

    def test_prepared_request_byte_body(self):
        request = EscherRequest(requests.Request('POST', 'http://localhost/?foo=bar', data=b'foo').prepare())

        self.assertEqual(request.body(), 'foo')

    def test_dict_add_header(self):
        request = EscherRequest({
            'method': 'GET',
            'url': '/?foo=bar',
        })

        self.assertFalse(request.has_header('bar'))
        request.add_header('Bar', 'baz')
        self.assertTrue(request.has_header('bar'))

    def test_prepared_request_add_header(self):
        request = EscherRequest(requests.Request('GET', 'http://localhost/?foo=bar').prepare())

        self.assertFalse(request.has_header('bar'))
        request.add_header('Bar', 'baz')
        self.assertTrue(request.has_header('bar'))
