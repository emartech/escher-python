import datetime
import hmac
import requests
import urllib
import re

from hashlib import sha256, sha512

try:
    from urlparse import urlparse, parse_qsl, urljoin
    from urllib import quote
except:
    from urllib.parse import urlparse, parse_qsl, urljoin, quote


class EscherRequestsAuth(requests.auth.AuthBase):
    def __init__(self, credential_scope, options, client):
        self.escher = Escher(credential_scope, options)
        self.client = client

    def __call__(self, request):
        return self.escher.sign(request, self.client)


class EscherRequest():
    _uri_regex = re.compile('([^?#]*)(\?(.*))?')

    def __init__(self, request):
        self.type = type(request)
        self.request = request
        self.prepare_request_uri()

    def request(self):
        return self.request

    def prepare_request_uri(self):
        if self.type is requests.models.PreparedRequest:
            self.request_uri = self.request.path_url
        if self.type is dict:
            self.request_uri = self.request['uri']
        match = re.match(self._uri_regex, self.request_uri)
        self.uri_path = match.group(1)
        self.uri_query = match.group(3)

    def method(self):
        if self.type is requests.models.PreparedRequest:
            return self.request.method
        if self.type is dict:
            return self.request['method']

    def host(self):
        if self.type is requests.models.PreparedRequest:
            return self.request.host
        if self.type is dict:
            return self.request['host']

    def path(self):
        return self.uri_path

    def query_parts(self):
        return parse_qsl((self.uri_query or '').replace(';', '%3b'), True)

    def headers(self):
        if self.type is requests.models.PreparedRequest:
            headers = []
            for key, value in self.request.headers.iteritems():
                headers.append([key, value])
            return headers
        if self.type is dict:
            return self.request['headers']

    def body(self):
        if self.type is requests.models.PreparedRequest:
            return self.request.body or ''
        if self.type is dict:
            return self.request.get('body', '')

    def add_header(self, header, value):
        if self.type is requests.models.PreparedRequest:
            self.request.headers[header] = value
        if self.type is dict:
            self.request['headers'].append((header, value))


class Escher:
    _normalize_path = re.compile('([^/]+/\.\./?|/\./|//|/\.$|/\.\.$)')

    def __init__(self, credential_scope, options={}):
        self.credential_scope = credential_scope
        self.algo_prefix = options.get('algo_prefix', 'ESR')
        self.vendor_key = options.get('vendor_key', 'Escher')
        self.hash_algo = options.get('hash_algo', 'SHA256')
        self.current_time = options.get('current_time', datetime.datetime.utcnow())
        self.auth_header_name = options.get('auth_header_name', 'X-Escher-Auth')
        self.date_header_name = options.get('date_header_name', 'X-Escher-Date')
        self.clock_skew = options.get('clock_skew', 900)
        self.algo = self.create_algo()
        self.algo_id = self.algo_prefix + '-HMAC-' + self.hash_algo

    def sign(self, r, client, headers_to_sign=[]):
        request = EscherRequest(r)

        for header in [self.date_header_name.lower(), 'host']:
            if header not in headers_to_sign:
                headers_to_sign.append(header)

        signature = self.generate_signature(client['api_secret'], request, headers_to_sign)
        request.add_header(self.auth_header_name, ", ".join([
            self.algo_id + ' Credential=' + client['api_key'] + '/' + self.short_date(
                self.current_time) + '/' + self.credential_scope,
            'SignedHeaders=' + self.prepare_headers_to_sign(headers_to_sign),
            'Signature=' + signature
        ]))
        return request.request

    def hmac_digest(self, key, message, is_hex=False):
        if not isinstance(key, bytes):
            key = key.encode('utf-8')
        digest = hmac.new(key, message.encode('utf-8'), self.algo)
        if is_hex:
            return digest.hexdigest()
        return digest.digest()

    def generate_signature(self, api_secret, req, headers_to_sign):
        canonicalized_request = self.canonicalize(req, headers_to_sign)
        string_to_sign = self.get_string_to_sign(canonicalized_request)

        signing_key = self.hmac_digest(self.algo_prefix + api_secret, self.short_date(self.current_time))
        for data in self.credential_scope.split('/'):
            signing_key = self.hmac_digest(signing_key, data)

        return self.hmac_digest(signing_key, string_to_sign, True)

    def canonicalize(self, req, headers_to_sign):
        return "\n".join([
            req.method(),
            self.canonicalize_path(req.path()),
            self.canonicalize_query(req.query_parts()),
            self.canonicalize_headers(req.headers()),
            '',
            self.prepare_headers_to_sign(headers_to_sign),
            self.algo(req.body().encode('utf-8')).hexdigest()
        ])

    def canonicalize_path(self, path):
        changes = 1
        while changes > 0:
            path, changes = self._normalize_path.subn('/', path, 1)
        return path

    def canonicalize_headers(self, headers):
        headers_list = []
        for key, value in iter(sorted(headers)):
            headers_list.append(key.lower() + ':' + self.normalize_white_spaces(value))
        return "\n".join(sorted(headers_list))

    def normalize_white_spaces(self, value):
        index = 0
        value_normalized = []
        pattern = re.compile(r'\s+')
        for part in value.split('"'):
            if index % 2 == 0:
                part = pattern.sub(' ', part)
            value_normalized.append(part)
            index += 1
        return '"'.join(value_normalized).strip()

    def canonicalize_query(self, query_parts):
        safe = "~+!'()*"
        query_list = []
        for key, value in query_parts:
            query_list.append(quote(key, safe=safe) + '=' + quote(value, safe=safe))
        return "&".join(sorted(query_list))

    def get_string_to_sign(self, canonicalized_request):
        return "\n".join([
            self.algo_id,
            self.long_date(self.current_time),
            self.short_date(self.current_time) + '/' + self.credential_scope,
            self.algo(canonicalized_request.encode('utf-8')).hexdigest()
        ])

    def create_algo(self):
        if self.hash_algo == 'SHA256':
            return sha256
        if self.hash_algo == 'SHA512':
            return sha512

    def long_date(self, time):
        return time.strftime('%Y%m%dT%H%M%SZ')

    def short_date(self, time):
        return time.strftime('%Y%m%d')

    def prepare_headers_to_sign(self, headers_to_sign):
        return ";".join(sorted(headers_to_sign))
