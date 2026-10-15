"""Security primitives extracted from Orbit; provenance in README.md."""
import certifi
import hashlib
import http.client
import ipaddress
import json
import socket
import ssl
import secrets
from urllib.parse import urlsplit
from pydantic import BaseModel, ConfigDict, Field

class Args(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)

class SaveArgs(Args):
    filename: str = Field(pattern=r'^[a-zA-Z0-9][a-zA-Z0-9_-]{0,79}\.(md|txt|csv|json)$')
    content: str = Field(min_length=1, max_length=50000)

def digest(name, arguments):
    return hashlib.sha256(json.dumps({'tool': name, 'arguments': arguments}, sort_keys=True, separators=(',', ':')).encode()).hexdigest()

def public_target(url):
    parsed = urlsplit(url)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.port not in (None, 443):
        raise ValueError('Only public HTTPS URLs on port 443 without embedded credentials are allowed.')
    if len(url) > 2048 or any(ord(c) < 32 for c in url):
        raise ValueError('Invalid URL.')
    host = parsed.hostname.encode('idna').decode('ascii')
    addresses = list({item[4][0] for item in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)})
    if not addresses or any(not ipaddress.ip_address(ip).is_global for ip in addresses):
        raise ValueError('Private, local, reserved, and metadata network addresses are blocked.')
    return parsed, host, addresses[0]

class PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, ip):
        super().__init__(host, timeout=12, context=ssl.create_default_context(cafile=certifi.where()))
        self.pinned_ip = ip

    def connect(self):
        # Resolve once, validate all results, connect to that exact address; TLS still validates the original host.
        sock = socket.create_connection((self.pinned_ip, 443), self.timeout)
        try:
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except Exception:
            sock.close()
            raise

def post_webhook(destination, payload, action_id):
    parsed, host, ip = public_target(destination)
    connection = PinnedHTTPS(host, ip)
    try:
        path = parsed.path or '/'
        if parsed.query:
            path += '?' + parsed.query
        body = json.dumps(payload, ensure_ascii=False, allow_nan=False).encode()
        connection.request('POST', path, body=body, headers={
            'Host': host, 'Content-Type': 'application/json', 'Accept': 'application/json,text/plain',
            'User-Agent': 'OrbitAutomation/1.1', 'Idempotency-Key': action_id,
        })
        response = connection.getresponse()
        # Do not follow redirects: they would change the user-approved destination.
        preview = response.read(4000).decode('utf-8', errors='replace')
        if not 200 <= response.status < 300:
            raise RuntimeError(f'Webhook returned HTTP {response.status}. Verify the automation run before sending again.')
        return {'accepted': True, 'http_status': response.status, 'response_preview': preview,
                'note': 'The endpoint accepted the request. This does not verify downstream automation completion.'}
    finally:
        connection.close()

def password_hash(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1).hex()
    return salt + ':' + digest
