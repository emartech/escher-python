import datetime
import hmac

import requests
import re

from hashlib import sha256, sha512

from urllib.parse import parse_qsl, quote, urlsplit, urlencode


class EscherException(Exception):
    pass


class EscherRequestsAuth(requests.auth.AuthBase):
    def __init__(self, api_key, api_secret, credential_scope, options=None):
        self.escher = Escher(api_key, api_secret, credential_scope, options)

    def __call__(self, request):
        return self.escher.sign_request(request)


class EscherRequest:
    _uri_regex = re.compile(r'([^?#]*)(\?(.*))?')

    def __init__(self, request):
        self.type = type(request)
        self.request = request
        self.is_presigned_url = False
        self.prepare_request_uri()

        if self.method() not in ('GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE', 'PATCH'):
            raise EscherException('The request method is invalid')

        if self.path().startswith('http://') or self.path().startswith('https://'):
            raise EscherException('The request url shouldn\'t contains http or https')

        if self.method() in ('POST', 'PUT', 'PATCH') and self.body() is None:
            raise EscherException(f'The request body shouldn\'t be empty if the request method is {self.method()}')

    def request(self):
        return self.request

    def prepare_request_uri(self):
        if self.type is requests.models.PreparedRequest:
            self.request_uri = self.request.path_url
        if self.type is dict:
            self.request_uri = self.request['url']
        match = re.match(self._uri_regex, self.request_uri)
        self.uri_path = match.group(1)
        self.uri_query = match.group(3)

    def method(self):
        if self.type is requests.models.PreparedRequest:
            return self.request.method.upper()
        if self.type is dict:
            return self.request['method'].upper()

    def host(self):
        if self.type is requests.models.PreparedRequest:
            return self.request.host
        if self.type is dict:
            return self.request['host']

    def path(self):
        return self.uri_path

    def query_parts(self):
        return parse_qsl((self.uri_query or '').replace(';', '%3b'), True)

    def has_query_param(self, query_param):
        return query_param.lower() in [key.lower() for key, value in self.query_parts()]

    def headers(self):
        if self.type is requests.models.PreparedRequest:
            headers = []
            for key, value in self.request.headers.items():
                headers.append([key, value])
            return headers
        if self.type is dict:
            return self.request['headers']

    def has_header(self, header):
        return header.lower() in [key.lower() for key, value in self.headers()]

    def body(self):
        if self.is_presigned_url:
            return 'UNSIGNED-PAYLOAD'
        if self.type is requests.models.PreparedRequest:
            return self.request.body.decode('utf-8') or None
        if self.type is dict:
            return self.request.get('body')

    def add_header(self, header, value):
        if self.type is requests.models.PreparedRequest:
            self.request.headers[header] = value
        if self.type is dict:
            self.request['headers'].append([header, value])

    def set_presigned_url(self, is_presigned_url):
        self.is_presigned_url = is_presigned_url


class AuthParams:
    @staticmethod
    def from_headers(headers, algo_prefix, date_header_name, auth_header_name):
        auth_data = None
        date_data = None
        for key, value in headers:
            if key.lower() == auth_header_name.lower():
                auth_data = value
            if key.lower() == date_header_name.lower():
                date_data = value

        pattern = re.compile(rf'^({algo_prefix}-HMAC-[A-Z0-9,]+).*Credential=([A-Za-z0-9/\-_ ]+),.*SignedHeaders=([A-Za-z\-;]+),.*Signature=([0-9a-f]+)$')

        if match := pattern.match(auth_data):
            g = match.groups()

            return AuthParams({
                'algorithm': g[0],
                'credentials': g[1],
                'signedheaders': g[2],
                'signature': g[3],
                'date': date_data,
            })
        else:
            raise EscherException('Could not parse auth header')

    @staticmethod
    def from_query_parts(query_parts, vendor_key):
        prefix = 'X-' + vendor_key + '-'
        data = {}
        for (k, v) in query_parts:
            if k.startswith(prefix):
                data[k.replace(prefix, '').lower()] = v

        return AuthParams(data)

    def __init__(self, data):
        self._data = data

    def get(self, name, default_value=None):
        value = self._data.get(name, default_value)
        if value is None:
            raise EscherException('Missing authorization parameter: ' + name)
        return value

    def get_signed_headers(self):
        return self.get('signedheaders').lower().split(';')

    def get_algo_data(self):
        data = self.get('algorithm').split('-')
        if len(data) != 3:
            raise EscherException('Malformed Algorithm parameter')
        return data

    def get_algo_prefix(self):
        return self.get_algo_data()[0]

    def get_hash_algo(self):
        return self.get_algo_data()[2].upper()

    def get_credential_data(self):
        data = self.get('credentials').split('/', 2)
        if len(data) != 3:
            raise EscherException('Malformed Credentials parameter')
        return data

    def get_credential_key(self):
        return self.get_credential_data()[0]

    def get_credential_date(self):
        return datetime.datetime.strptime(self.get_credential_data()[1], '%Y%m%d').replace(tzinfo=datetime.timezone.utc)

    def get_credential_scope(self):
        return self.get_credential_data()[2]

    def get_expires(self):
        return int(self.get('expires', 0))

    def get_request_date(self):
        try:
            return datetime.datetime.strptime(self.get('date'), '%Y%m%dT%H%M%SZ').replace(tzinfo=datetime.timezone.utc)
        except ValueError:
            return datetime.datetime.strptime(self.get('date'), '%a, %d %b %Y %H:%M:%S GMT').replace(tzinfo=datetime.timezone.utc)


class AuthenticationValidator:
    def validate_mandatory_signed_headers(self, mandatory_signed_headers, headers_to_sign):
        for header in mandatory_signed_headers:
            if header not in headers_to_sign:
                raise EscherException(f'The {header} header is not signed')

    def validate_hash_algo(self, hash_algo):
        if hash_algo not in ('SHA256', 'SHA512'):
            raise EscherException('Only SHA256 and SHA512 hash algorithms are allowed')

    def validate_dates(self, current_date, request_date, credential_date, expires, clock_skew):
        if request_date.strftime('%Y%m%d') != credential_date.strftime('%Y%m%d'):
            raise EscherException('The credential date does not match with the request date')

        min_date = current_date - datetime.timedelta(seconds=(clock_skew + expires))
        max_date = current_date + datetime.timedelta(seconds=clock_skew)
        if request_date < min_date or request_date > max_date:
            raise EscherException('The request date is not within the accepted time range')

    def validate_credential_scope(self, expected, actual):
        if actual != expected:
            raise EscherException('The credential scope is invalid')

    def validate_signature(self, expected, actual):
        if expected != actual:
            raise EscherException('The signatures do not match')


class Escher:
    _normalize_path = re.compile(r'([^/]+/\.\./?|/\./|//|/\.$|/\.\.$)')

    def __init__(self, api_key, api_secret, credential_scope, options=None):
        if not options:
            options = {}
        self.api_key = api_key
        self.api_secret = api_secret
        self.credential_scope = credential_scope
        self.algo_prefix = options.get('algo_prefix', 'ESR')
        self.vendor_key = options.get('vendor_key', 'Escher')
        self.hash_algo = options.get('hash_algo', 'SHA256')
        self.current_time = options.get('current_time')
        self.auth_header_name = options.get('auth_header_name', 'X-Escher-Auth')
        self.date_header_name = options.get('date_header_name', 'X-Escher-Date')
        self.clock_skew = options.get('clock_skew', 300)
        self.algo = self.create_algo()
        self.algo_id = self.algo_prefix + '-HMAC-' + self.hash_algo

    def sign_request(self, request, headers_to_sign=None):
        request = EscherRequest(request)
        request.set_presigned_url(False)

        if not self.api_key or not self.api_secret:
            raise EscherException('Invalid Escher key')

        if not headers_to_sign:
            headers_to_sign = []
        headers_to_sign = [h.lower() for h in headers_to_sign]

        for header in [self.date_header_name.lower(), 'host']:
            if header not in headers_to_sign:
                headers_to_sign.append(header)

        current_time = self.current_time or datetime.datetime.now(datetime.timezone.utc)

        if not request.has_header(self.date_header_name):
            if self.date_header_name.lower() == 'date':
                request.add_header(self.date_header_name, self.header_date(current_time))
            else:
                request.add_header(self.date_header_name, self.long_date(current_time))

        signature = self.generate_signature(self.api_secret, request, headers_to_sign, current_time)
        request.add_header(self.auth_header_name, ", ".join([
            self.algo_id + ' Credential=' + self.api_key + '/' + self.short_date(
                current_time) + '/' + self.credential_scope,
            'SignedHeaders=' + self.prepare_headers_to_sign(headers_to_sign),
            'Signature=' + signature
        ]))
        return request.request

    def presign_url(self, url, expires):
        current_time = self.current_time or datetime.datetime.now(datetime.timezone.utc)

        if not self.api_key or not self.api_secret:
            raise EscherException('Invalid Escher key')

        url_to_sign = url + ('&' if '?' in url else '?') + urlencode({
            f'X-{self.vendor_key}-Algorithm': self.algo_id,
            f'X-{self.vendor_key}-Credentials': self.api_key + '/' + self.short_date(current_time) + '/' + self.credential_scope,
            f'X-{self.vendor_key}-Date': self.long_date(current_time),
            f'X-{self.vendor_key}-Expires': expires,
            f'X-{self.vendor_key}-SignedHeaders': 'host',
        })

        parts = urlsplit(url_to_sign)
        request = EscherRequest({
            'method': 'GET',
            'url': f'{parts.path}?{parts.query}',
            'headers': [['host', parts.netloc]],
        })
        request.set_presigned_url(True)
        signature = self.generate_signature(self.api_secret, request, ['host'], current_time)

        return url_to_sign + '&' + urlencode({
            f'X-{self.vendor_key}-Signature': signature,
        })

    def authenticate(self, request, key_db, mandatory_signed_headers=None):
        current_time = self.current_time or datetime.datetime.now(datetime.timezone.utc)

        request = EscherRequest(request)

        if mandatory_signed_headers is None:
            mandatory_signed_headers = []
        if not isinstance(mandatory_signed_headers, list) or not all([isinstance(h, str) for h in mandatory_signed_headers]):
            raise EscherException('The mandatorySignedHeaders parameter must be undefined or array of strings')
        mandatory_signed_headers = [h.lower() for h in mandatory_signed_headers]
        mandatory_signed_headers.append('host')

        if self.auth_header_name and request.has_header(self.auth_header_name):
            auth_params = AuthParams.from_headers(request.headers(), self.algo_prefix, self.date_header_name, self.auth_header_name)
            request.set_presigned_url(False)
            mandatory_signed_headers.append(self.date_header_name.lower())
        elif request.method() == 'GET' and request.has_query_param(f'X-{self.vendor_key}-Signature'):
            auth_params = AuthParams.from_query_parts(request.query_parts(), self.vendor_key)
            request.set_presigned_url(True)
        else:
            raise EscherException('The authorization header is missing')

        validator = AuthenticationValidator()
        validator.validate_mandatory_signed_headers(mandatory_signed_headers, auth_params.get_signed_headers())
        for header in mandatory_signed_headers:
            if not request.has_header(header):
                raise EscherException(f'The {header} header is missing')

        validator.validate_hash_algo(auth_params.get_hash_algo())
        validator.validate_dates(
            current_time,
            auth_params.get_request_date(),
            auth_params.get_credential_date(),
            auth_params.get_expires(),
            self.clock_skew
        )
        validator.validate_credential_scope(self.credential_scope, auth_params.get_credential_scope())

        if auth_params.get_credential_key() not in key_db:
            raise EscherException('Invalid Escher key')

        calculated_signature = self.generate_signature(
            key_db[auth_params.get_credential_key()], request,
            auth_params.get_signed_headers(),
            auth_params.get_request_date()
        )
        validator.validate_signature(calculated_signature, auth_params.get('signature'))

        return auth_params.get_credential_key()

    def hmac_digest(self, key, message, is_hex=False):
        if not isinstance(key, bytes):
            key = key.encode('utf-8')
        digest = hmac.new(key, message.encode('utf-8'), self.algo)
        if is_hex:
            return digest.hexdigest()
        return digest.digest()

    def generate_signature(self, api_secret, req, headers_to_sign, current_time):
        canonicalized_request = self.canonicalize(req, headers_to_sign)
        string_to_sign = self.get_string_to_sign(canonicalized_request, current_time)

        signing_key = self.hmac_digest(self.algo_prefix + api_secret, self.short_date(current_time))
        for data in self.credential_scope.split('/'):
            signing_key = self.hmac_digest(signing_key, data)

        return self.hmac_digest(signing_key, string_to_sign, True)

    def canonicalize(self, req, headers_to_sign):
        return "\n".join([
            req.method(),
            self.canonicalize_path(req.path()),
            self.canonicalize_query(req.query_parts()),
            self.canonicalize_headers(req.headers(), headers_to_sign),
            '',
            self.prepare_headers_to_sign(headers_to_sign),
            self.algo(req.body().encode('utf-8')).hexdigest()
        ])

    def canonicalize_path(self, path):
        changes = 1
        while changes > 0:
            path, changes = self._normalize_path.subn('/', path, 1)
        return path

    def canonicalize_headers(self, headers, headers_to_sign):
        results = {}
        for key, value in headers:
            if key.lower() not in headers_to_sign:
                continue

            if key.lower() in results:
                results[key.lower()] += ',' + self.normalize_white_spaces(value)
            else:
                results[key.lower()] = self.normalize_white_spaces(value)

        return "\n".join([f'{key}:{results[key]}' for key in sorted(results.keys())])

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
        safe = "~+!'*"
        query_list = []
        for key, value in query_parts:
            if key == 'X-' + self.vendor_key + '-Signature':
                continue
            query_list.append(quote(key, safe=safe) + '=' + quote(value, safe=safe))
        return "&".join(sorted(query_list))

    def get_string_to_sign(self, canonicalized_request, current_time):
        return "\n".join([
            self.algo_id,
            self.long_date(current_time),
            self.short_date(current_time) + '/' + self.credential_scope,
            self.algo(canonicalized_request.encode('utf-8')).hexdigest()
        ])

    def create_algo(self):
        if self.hash_algo == 'SHA256':
            return sha256
        if self.hash_algo == 'SHA512':
            return sha512

    def header_date(self, time):
        return time.strftime('%a, %d %b %Y %H:%M:%S GMT')

    def long_date(self, time):
        return time.strftime('%Y%m%dT%H%M%SZ')

    def short_date(self, time):
        return time.strftime('%Y%m%d')

    def prepare_headers_to_sign(self, headers_to_sign):
        return ";".join(sorted(headers_to_sign))
