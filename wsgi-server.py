import os
from io import BytesIO
import socket
import signal # Allow socket destruction on Ctrl+C
import sys
import time
import threading
from concurrent.futures.thread import ThreadPoolExecutor
import threading
from typing import NamedTuple
from wsgiref.simple_server import make_server, demo_app

executor = ThreadPoolExecutor(max_workers=10, thread_name_prefix='request_handler')


class RequestContext:
    # TODO
    pass


class HTTPRequest:

    def __init__(self, request_method, path, query, http_protocol, body=None, headers=None):
        self.request_method = request_method
        self.path = path
        self.query = query
        self.http_protocol = http_protocol
        self.headers = headers
        self.body = body


class WSGIServer(object):

    def __init__(self, host='', port=5000, app=None, max_handlers=5):

        self.host = host
        self.port = port
        self.content_dir = 'web'
        self.app = app
        self.max_handlers = max_handlers
        self.request_context = threading.local()

    def set_app(self, app):
        self.app = app

    def start(self):

        if self.app is None or not callable(self.app):
            raise ValueError("Invalid wsgi application.")

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            print("Starting server on {host}:{port}".format(host=self.host, port=self.port))
            self.socket.bind((self.host, self.port))
            print("Server started on port {port}.".format(port=self.port))

        except Exception as e:
            print("Error: Could not bind to port {port}".format(port=self.port))
            self.shutdown()
            sys.exit(1)

        self._listen() # Start listening for connections

    def shutdown(self):

        try:
            print("Shutting down server")
            self.socket.shutdown(socket.SHUT_RDWR)

        except Exception as e:
            pass # Pass if socket is already closed

    def _listen(self):

        self.socket.listen(self.max_handlers)
        try:
            while True:
                conn, address = self.socket.accept()
                print("Recieved connection from {addr}".format(addr=address))
                executor.submit(self._handle_request, conn, address)
        except KeyboardInterrupt:
            print('Server stopped.')

    def get_request_headers(self, header_bytes) -> dict:
        headers = {}
        headers_str = header_bytes.decode()
        request_line, *headers_key_values = headers_str.split('\r\n')
        request_method, path_and_query, http_protocol = request_line.split(' ')
        if '?' in path_and_query:
            path, query = path_and_query.split('?')
        else:
            path = path_and_query
            query = ''
        for header_kv in headers_key_values:
            key, value = header_kv.split(': ')
            headers[key] = value
        self.request_context.request = HTTPRequest(request_method, path, query, http_protocol,
                                                   headers=headers.copy())
        return headers

    def get_env(self):

        env = dict(os.environ.items())
        request = self.request_context.request
        env['PATH_INFO'] = request.path
        env['QUERY_STRING'] = request.query
        env['SERVER_PROTOCOL'] = request.http_protocol
        env['REQUEST_METHOD'] = request.request_method
        env['wsgi.input'] = BytesIO(request.body)
        env['wsgi.errors'] = sys.stderr
        env['wsgi.version'] = (1, 0)
        env['wsgi.multithread'] = True
        env['wsgi.multiprocess'] = True
        env['wsgi.run_once'] = False
        env['SERVER_NAME'] = "Simple WSGI Server"
        env['GATEWAY_INTERFACE'] = 'CGI/1.1'
        env['SERVER_PORT'] = str(self.port)
        env['REMOTE_HOST'] = '' # TODO
        env['CONTENT_LENGTH'] = request.headers.get('Content-Length', '')
        env['CONTENT_TYPE'] = request.headers.get('Content-Type', '')
        env['SCRIPT_NAME'] = ''
        if env.get('HTTPS', 'off') in ('on', '1'):
            env['wsgi.url_scheme'] = 'https'
        else:
            env['wsgi.url_scheme'] = 'http'
        for header_key, header_value in request.headers.items():
            header_key = header_key.replace('-', '_').upper()
            header_value = header_value.strip()
            if header_key in env:
                continue
            if f'HTTP_{header_key}' in env:
                env[f'HTTP_{header_key}'] += ',' + header_value
            else:
                env[f'HTTP_{header_key}'] = header_value
        return env

    def _handle_request(self, conn, address):
        content_length = 0
        headers_bytes = body_bytes = b''
        headers_completely_received = False

        while True:
            recv = conn.recv(1024)
            if not recv:
                conn.close()
                raise Exception('请求中断')

            if not headers_completely_received:
                headers_bytes += recv
                if b'\r\n\r\n' in headers_bytes:
                    headers_completely_received = True
                    headers_bytes, body_bytes = headers_bytes.split(b'\r\n\r\n')
                    headers = self.get_request_headers(headers_bytes)
                    if 'Content-Length' in headers:
                        content_length = int(headers['Content-Length'])
                    if content_length == 0 or content_length == len(body_bytes):
                    # 没有body或者body在当前recv中已经一起取完的情况
                        break
            else:
                body_bytes += recv
                if len(body_bytes) >= content_length:
                    break

        self.request_context.request.body = body_bytes
        environ = self.get_env()

        results = self.app(environ, self.start_response)
        resp_headers_str = resp_body_str = ''
        resp_headers_str += f'{self.request_context.request.http_protocol} {self.request_context.status}\r\n'
        for header_key, header_value in self.request_context.response_headers:
            resp_headers_str += f'{header_key}: {header_value}\r\n'
        resp_headers_str += f'\r\n'
        for result in results:
            resp_body_str += result.decode()
        response = resp_headers_str + resp_body_str
        self.clear_request_context()

        conn.sendall(response.encode())
        conn.close()

    def clear_request_context(self):
        del self.request_context.request
        del self.request_context.status
        del self.request_context.response_headers

    def start_response(self, status, response_headers):
        self.request_context.status = status
        self.request_context.response_headers = response_headers


if __name__ == '__main__':

    from flask import Flask, request, jsonify
    app = Flask(__name__)
    @app.route('/')
    def hello():
        return jsonify({**request.json, **request.args.to_dict(), **request.headers})

    WSGIServer(app=app).start()
