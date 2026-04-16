import requests
import logging
import time
import json
import base64
from typing import Dict

def make_request_with_retry(session, method, url, max_retries=5, auth=None, **kwargs):
    """Make a request with retry logic for proxy/connection errors."""
    for attempt in range(max_retries):
        try:
            # time.sleep(0.1)  # Base delay between all requests
            if method == 'GET':
                return session.get(url, allow_redirects=False, timeout=10, stream=True, auth=auth, **kwargs)
            elif method == 'POST':
                return session.post(url, allow_redirects=False, timeout=10, stream=True, auth=auth, **kwargs)
        except (requests.exceptions.ProxyError, 
                requests.exceptions.ConnectionError,
                requests.exceptions.Timeout,
                requests.exceptions.ChunkedEncodingError) as e:
            if attempt < max_retries - 1:
                wait_time = (2 ** attempt) + (0.1 * attempt)  # Exponential backoff: 1s, 2.1s, 4.2s, 8.3s
                logging.error(f"Connection error (attempt {attempt + 1}/{max_retries}), retrying in {wait_time:.1f}s: {type(e).__name__}")
                time.sleep(wait_time)
                continue
            logging.critical(f"Max retries exceeded for {url}")
            raise e
        
def pretty_print_request(req: requests.PreparedRequest):
    out = f"{req.method} {req.url} HTTP/1.1\n"
    for k, v in req.headers.items():
        out += f"{k}: {v}\n"
    if req.body:
        out += "\n"
        out += f"{req.body}\n"
    return out

def pretty_print_response(r: requests.Response):
    out = f"HTTP/1.1 {r.status_code} {r.reason}\n"
    for k, v in r.headers.items():
        out += f"{k}: {v}\n"
    out += "\n"
    out += r.text
    out += "\n"
    return out

def encode_jwt(payload, header=None) -> str:
    """Encode a JWT with the given payload using 'none' algorithm."""
    if isinstance(payload, dict):
        payload_str = json.dumps(payload, separators=(',', ':'))  # Compact encoding
    else:
        payload_str = payload
    if header is None:
        header = {"alg": "none"}
    header = json.dumps(header, separators=(',', ':'))
    return f"{base64.urlsafe_b64encode(header.encode()).rstrip(b'=').decode()}.{base64.urlsafe_b64encode(payload_str.encode()).rstrip(b'=').decode()}."

def decode_jwt(token) -> Dict:
    """Decode a JWT without verifying the signature."""
    try:
        header_b64, payload_b64, signature = token.split('.')
        payload_json = base64.urlsafe_b64decode(payload_b64 + '==').decode()
        return payload_json
    except Exception as e:
        logging.error(f"Error decoding JWT: {e}")
        return {}