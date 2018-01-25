import hmac
from hashlib import sha256
from base64 import b64encode, b64decode
from urllib import request
from urllib.error import URLError
import time

# Detectify public API endpoint, no trailing slash
ENDPOINT = 'https://api.detectify.com/rest/v2'


def make_headers(api_key, secret_key, method, path, timestamp, body=None):
    method = method.upper()
    signature = make_signature(api_key, secret_key, method, path, timestamp, body)

    return {
        'X-Detectify-Key': api_key,
        'X-Detectify-Signature': signature,
        'X-Detectify-Timestamp': timestamp
    }


def make_signature(api_key, secret_key, method, path, timestamp, body=None):
    msg = f"{method};{path};{api_key};{timestamp};"
    if body:
        msg += body

    msg_bytes = msg.encode()
    secret = b64decode(secret_key)

    sig_bytes = hmac.new(key=secret, msg=msg_bytes, digestmod=sha256)
    sig_base64 = b64encode(sig_bytes.digest())

    return sig_base64.decode()


def start_scan(scan_profile, api_key, secret_key):
    path = f"/scans/{scan_profile}/"
    url = f"{ENDPOINT}{path}"
    timestamp = int(time.time())
    headers = make_headers(api_key, secret_key, 'POST', path, timestamp)

    # API response codes
    response_codes = {
        202: 'Scan start request accepted',
        400: 'Invalid scan profile token',
        401: 'Missing/invalid API key or message signature, or invalid timestamp',
        403: 'The API key cannot access this functionality',
        409: 'A scan is already running on the specified profile',
        423: 'The domain is not verified',
        500: 'An error occurred while processing the request',
        503: 'An error occurred while processing the request',
    }

    req = request.Request(url, headers=headers, method='POST')
    try:
        response = request.urlopen(req)
    except URLError as e:
        if hasattr(e, 'code'):
            print(response_codes.get(e.code))
    else:
        if hasattr(response, 'code'):
            print(response_codes.get(response.code))


def scan_status(scan_profile, api_key, secret_key):
    path = f"/scans/{scan_profile}/"
    url = f"{ENDPOINT}{path}"
    timestamp = int(time.time())
    headers = make_headers(api_key, secret_key, 'GET', path, timestamp)

    # API response codes
    response_codes = {
        200: 'Returned scan status',
        400: 'Bad request',
        401: 'Missing/invalid API key or message signature, or invalid timestamp',
        403: 'The API key cannot access this functionality',
        404: 'No scan running for the specified profile, or the specified scan profile ' +
             'does not exist or the API key cannot access the scan profile',
        500: 'An error occurred while processing the request',
        503: 'An error occurred while processing the request',
    }

    req = request.Request(url, headers=headers, method='GET')
    try:
        response = request.urlopen(req)
    except URLError as e:
        if hasattr(e, 'code'):
            print(response_codes.get(e.code))
    else:
        if hasattr(response, 'code'):
            print(response_codes.get(response.code))
            print(response.read().decode())


scanProfile = '5605b488634efe810dff4276e28ca7f9'
apiKey = 'd4bf676ee6146557cbf0f28fe6cbc290'
secretKey = 'SGVsbG8sIHdvcmxkISBJIGFtIGEgdGVhcG90IQ=='

start_scan(scanProfile, apiKey, secretKey)
scan_status(scanProfile, apiKey, secretKey)
