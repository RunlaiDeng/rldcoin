#!/usr/bin/env python3
"""Bounded loopback proxy with explicit worthless-test-currency responses."""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import re
import threading
import urllib.error
import urllib.request

SLOTS = threading.BoundedSemaphore(16)
ROUTES = {
    'earth': {'GET': r'(status|continuity|finality|escrows/[0-9a-f]{64}|commands/[0-9a-f]{64})',
              'POST': r'(template|blocks|sync|pending|commands)'},
    'earth-destination': {'GET': r'(status|balance/[0-9a-f]{64})',
                          'POST': r'(template|blocks|sync|receipts|verify-receipt)'},
}


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def reply(self, code, body):
        body.update(test_only=True, has_monetary_value=False, mainnet_authorized=False, live_rld=False)
        data = json.dumps(body, separators=(',', ':')).encode()
        self.send_response(code)
        for k, v in {'Content-Type':'application/json','Content-Length':str(len(data)),
                     'Cache-Control':'no-store','X-Rld-Network':'testnet','Connection':'close'}.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)
        self.close_connection = True

    def dispatch(self):
        if not SLOTS.acquire(blocking=False):
            return self.reply(503, {'error':'Test gateway busy'})
        try:
            match = re.fullmatch(r'/v1/testnet/(earth|earth-destination)/(.*)', self.path)
            if not match or not re.fullmatch(ROUTES[match[1]].get(self.command, r'(?!)'), match[2]):
                return self.reply(404, {'error':'Unknown testnet route'})
            size = self.headers.get('Content-Length', '0')
            if not size.isdecimal() or int(size) > 3*1024*1024 or self.headers.get('Transfer-Encoding'):
                return self.reply(413, {'error':'Invalid request size'})
            self.connection.settimeout(15)
            body = self.rfile.read(int(size)) if self.command == 'POST' else None
            port = 48500 if match[1] == 'earth' else 48510
            request = urllib.request.Request(f'http://127.0.0.1:{port}/v1/{match[1]}/{match[2]}',
                                              data=body, method=self.command,
                                              headers={'Content-Type':'application/json','Accept':'application/json'})
            try:
                response = urllib.request.urlopen(request, timeout=25)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                raw = response.read(8*1024*1024+1)
                if len(raw) > 8*1024*1024:
                    raise ValueError('response exceeded bound')
                data = json.loads(raw)
                if not isinstance(data, dict):
                    data = {'result':data, 'testnet_result_envelope':True}
                return self.reply(response.status, data)
        except (OSError, ValueError, TimeoutError):
            return self.reply(503, {'error':'Test node unavailable'})
        finally:
            SLOTS.release()

    do_GET = dispatch
    do_POST = dispatch

    def log_message(self, *args):
        pass


if __name__ == '__main__':
    server = ThreadingHTTPServer(('127.0.0.1',48540), Handler)
    server.daemon_threads = True
    server.serve_forever()
