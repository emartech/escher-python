EscherPython - HTTP request signing lib [![Build Status](https://github.com/emartech/escher-python/actions/workflows/python.yml/badge.svg)](https://github.com/emartech/escher-python/actions)
=======================================

Escher helps you creating secure HTTP requests (for APIs) by signing HTTP(s) requests. It's both a server side and client side implementation. The status is work in progress.

The algorithm is based on [Amazon's _AWS Signature Version 4_](http://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-authenticating-requests.html), but we have generalized and extended it.

More details are available at [escherauth.io](http://escherauth.io/).

Signing a request
-----------------

Escher works by calculating a cryptographic signature of your request, and adding it (and other authentication information) to said request.

Usually you will want to add the authentication information to the request by appending extra headers to it.

```python
from escherauth import Escher

request = {
    'method': 'POST',
    'url': '/',
    'headers': [
        ['Host', 'example.com'],
    ],
    'body': '{"this_is": "a_request_body"}',
}

escher = Escher('YOUR_ACCESS_KEY_ID', 'YOUR SECRET', 'example/credential/scope')
signed_request = escher.sign_request(request)

from pprint import pprint
pprint(signed_request)
```

Signing a [Requests](https://requests.readthedocs.io/) request:

```python
import requests
from escherauth import EscherRequestsAuth

auth = EscherRequestsAuth('YOUR_ACCESS_KEY_ID', 'YOUR SECRET', 'example/credential/scope')
response = requests.post('https://httpbin.org/post', json={'this_is': 'a_request_body'}, auth=auth)

from pprint import pprint
pprint(response.json())
```

Presigning a URL
----------------

In some cases you may want to send authenticated requests from a context where you cannot modify the request headers, e.g. when embedding an API generated iframe.

You can however generate a presigned URL, where the authentication information is added to the query string.

```python
from escherauth import Escher

escher = Escher('YOUR_ACCESS_KEY_ID', 'YOUR SECRET', 'example/credential/scope')
presigned_url = escher.presign_url('http://example.com/', expires=300)

print(presigned_url)
```

Validating a request
--------------------

You can validate a request signed by the methods described above. For that you will need a database of the access keys and secrets of your clients.

```python
from escherauth import Escher, EscherException

escher = Escher('', '', 'example/credential/scope')

signed_request = {
    'body': '{"this_is": "a_request_body"}',
    'headers': [
        ['Host', 'example.com'],
        ['X-Escher-Date', '20240227T121443Z'],
        ['X-Escher-Auth', 'ESR-HMAC-SHA256 Credential=YOUR_ACCESS_KEY_ID/20240227/example/credential/scope, SignedHeaders=host;x-escher-date, Signature=5febb099193b8e6c4027ff810e0faa5bc8a275efb46f2d5c1af8810f4332c4cb'],
    ],
    'method': 'POST',
    'url': '/',
}
key_db = {
    'ACCESS_KEY_OF_CLIENT_1': 'SECRET OF CLIENT 1',
    'ACCESS_KEY_OF_CLIENT_42': 'SECRET OF CLIENT 42',
}

try:
    escher.authenticate(signed_request, key_db)
    print('OK')
except EscherException as e:
    print(f'The validation failed: {e}')
```
