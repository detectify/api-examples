import requests
import hmac
import hashlib
import json
import os

from base64 import b64encode, b64decode
from datetime import datetime

ENDPOINT = "https://api.detectify.com/rest"
api_key = os.getenv("API_KEY")
api_secret_key = os.getenv("API_SECRET_KEY")


def send_post_request(data: dict or None, path: str, url: str) -> dict or None:
    timestamp = str(int(datetime.now().timestamp()))

    if data:
        headers = make_headers("POST", path, timestamp, json.dumps(data))
        req = requests.post(url, headers=headers, data=json.dumps(data))
    else:
        headers = make_headers("POST", path, timestamp, None)
        req = requests.post(url, headers=headers, data=None)

    try:
        req.raise_for_status()
    except Exception as e:
        print(e)
        return None

    print(f"Status code: {req.status_code} | Raw response: {req.json()}")
    return req.json()


def make_headers(method: str, path: str, timestamp: str, body: str = None):
    method = method.upper()
    signature = make_signature(method, path, timestamp, body)
    return {
        "X-Detectify-Key": api_key,
        "X-Detectify-Signature": signature,
        "X-Detectify-Timestamp": timestamp,
    }


def make_signature(method: str, path: str, timestamp: str, body: str = None):
    msg = f"{method};{path};{api_key};{timestamp};"
    if body:
        msg += f"{body}"

    secret = b64decode(api_secret_key)
    signature = hmac.new(
        secret, msg=bytes(msg, "utf=8"), digestmod=hashlib.sha256
    ).digest()

    b64_sig = b64encode(signature)
    return b64_sig.decode("utf-8")


def _create_add_domain_payload(domain: str) -> dict:
    data = {"name": f"{domain}"}
    return data


def add_domain(domain: str):
    path = "/v2/domains/"
    url = f"{ENDPOINT}{path}"
    data = _create_add_domain_payload(domain)
    send_post_request(data, path, url)


def _add_scan_profile_payload(scan_profile: str) -> dict:
    return {"endpoint": scan_profile, "unique": True}


def add_scan_profile(scan_profile: str) -> str or None:
    path = "/v2/profiles/"
    url = f"{ENDPOINT}{path}"
    data = _add_scan_profile_payload(scan_profile)
    resp = send_post_request(data, path, url)
    if resp is not None:
        scan_profile_token = resp.get("token", None)
        return scan_profile_token

    return None


def start_scan(scan_profile_token: str):
    path = f"/v2/scans/{scan_profile_token}/"
    url = f"{ENDPOINT}{path}"
    resp = send_post_request(None, path, url)
    if resp is not None:
        print(resp)


if __name__ == "__main__":
    add_domain("abcd.com")
    sp_token = add_scan_profile("my.abcd.com")
    start_scan(sp_token)
