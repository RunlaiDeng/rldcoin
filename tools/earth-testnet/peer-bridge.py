#!/usr/bin/env python3
"""Public testnet RPC adapter for pinned fixture nodes; binds only loopback."""
import argparse
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, HTTPRedirectHandler, build_opener
from gateway import ROUTES
from run import IMPLEMENTATION

ORIGIN = 'https://api.rldcoin.com/v1/testnet'
CHAINS = {
    'earth': 'e8a8dd66eac5a8fe70816901c6b06035fc92b2193213d8fa0f00d2f10a32438e',
    'earth-destination': '6f952ed6eff0aa16d27bd18ab6c760357a21770a954952fffeb4852537c5363a',
}


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch(region, path, method='GET', body=None):
    request = Request(f'{ORIGIN}/{region}/{path}', data=body, method=method,
                      headers={'Content-Type': 'application/json'})
    try:
        response = build_opener(NoRedirect).open(request, timeout=20)
    except HTTPError as error:
        response = error
    with response:
        raw = response.read(8*1024*1024+1)
        if len(raw) > 8*1024*1024:
            raise ValueError('test response exceeds budget')
        data = json.loads(raw)
        if not isinstance(data, dict) or any(data.get(k) is not v for k, v in {
            'test_only': True, 'has_monetary_value': False,
            'mainnet_authorized': False, 'live_rld': False,
        }.items()):
            raise ValueError('upstream is not the explicitly worthless testnet')
        for key in ['test_only', 'has_monetary_value', 'mainnet_authorized', 'live_rld']:
            del data[key]
        if data.pop('testnet_result_envelope', False) is True:
            if set(data) != {'result'}:
                raise ValueError('invalid testnet result envelope')
            data = data['result']
        if path in ['status', 'continuity'] and response.status == 200:
            # Native "live_rld" means signed adopted mode. Only this PRIVATE
            # fixture adapter normalizes it; no public money/value claim changes.
            data['live_rld'] = True
        return response.status, data


class BoundedServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 8

    def __init__(self, *args, **kwargs):
        self.slots = threading.BoundedSemaphore(8)
        super().__init__(*args, **kwargs)

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            return self.shutdown_request(request)
        request.settimeout(10)
        try:
            super().process_request(request, address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()


class Handler(BaseHTTPRequestHandler):
    def dispatch(self):
        try:
            region = self.server.region
            match = re.fullmatch(f'/v1/{region}/(.{{1,130}})', self.path)
            if not match or not re.fullmatch(ROUTES[region].get(self.command, r'(?!)'), match[1]):
                return self.send_error(404)
            lengths = self.headers.get_all('Content-Length', [])
            if len(lengths) > 1 or self.headers.get('Transfer-Encoding'):
                return self.send_error(400)
            size = lengths[0] if lengths else '0'
            if not re.fullmatch(r'0|[1-9][0-9]{0,9}', size) or int(size) > 3*1024*1024:
                return self.send_error(413)
            body = self.rfile.read(int(size)) if self.command == 'POST' else None
            if body is not None and len(body) != int(size):
                return self.send_error(408)
            code, data = fetch(region, match[1], self.command, body)
            encoded = json.dumps(data, separators=(',', ':')).encode()
            self.send_response(code)
            for key, value in {'Content-Type': 'application/json', 'Content-Length':str(len(encoded)),
                               'Cache-Control':'no-store', 'X-Rld-Network':'testnet', 'Connection':'close'}.items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(encoded)
            self.close_connection = True
        except (OSError, ValueError, TimeoutError):
            self.send_error(503, 'Testnet adapter unavailable')

    do_GET = dispatch
    do_POST = dispatch

    def log_message(self, *args):
        pass


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--region', choices=CHAINS, required=True)
    parser.add_argument('--port', type=int, required=True)
    args = parser.parse_args()
    if not 48530 <= args.port <= 48599:
        raise ValueError('port must be within the test-only loopback range')
    code, status = fetch(args.region, 'status')
    key = 'chain_id' if args.region == 'earth' else 'destination_chain_id'
    if code != 200 or status.get(key) != CHAINS[args.region] or status.get('implementation_source_sha256') != IMPLEMENTATION:
        raise ValueError('public testnet identity differs from pinned fixture')
    server = BoundedServer(('127.0.0.1', args.port), Handler)
    server.region = args.region
    server.serve_forever()
