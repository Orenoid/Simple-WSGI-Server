import os
import socket
import signal # Allow socket destruction on Ctrl+C
import sys
import time
import threading
from concurrent.futures.thread import ThreadPoolExecutor
import threading

executor = ThreadPoolExecutor(max_workers=10, thread_name_prefix='client_handler')

class WebServer(object):
    """
    Class for describing simple HTTP server objects
    """

    def __init__(self, host='127.0.0.1', port=8080, app=None):
        # self.host = socket.gethostname().split('.')[0] # Default to any avialable network interface
        self.host = host
        self.port = port
        self.content_dir = 'web'
        self.app = app
        self.response = threading.local()

    def set_app(self, app):
        self.app = app

    def start(self):
        """
        Attempts to create and bind a socket to launch the server
        """
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
        """
        Shuts down the server
        """
        try:
            print("Shutting down server")
            self.socket.shutdown(socket.SHUT_RDWR)

        except Exception as e:
            pass # Pass if socket is already closed

    def _listen(self):
        """
        Listens on self.port for any incoming connections
        """
        self.socket.listen(5)
        try:
            while True:
                (client, address) = self.socket.accept()
                # client.settimeout(60)
                print("Recieved connection from {addr}".format(addr=address))
                # threading.Thread(target=self._handle_client, args=(client, address)).start()
                executor.submit(self._handle_client, client, address)
        except KeyboardInterrupt:
            print('Server stopped.')

    def _generate_headers(self, response_code):

        header = ''
        if response_code == 200:
            header += 'HTTP/1.1 200 OK\n'
        elif response_code == 404:
            header += 'HTTP/1.1 404 Not Found\n'

        time_now = time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime())
        header += 'Date: {now}\n'.format(now=time_now)
        header += 'Server: Simple-Python-Server\n'
        header += 'Connection: close\n\n' # Signal that connection will be closed after completing the request
        return header


    def _handle_client(self, conn, address):

        PACKET_SIZE = 1024
        headers = {}
        content_length = 0
        headers_bytes = body_bytes = b''
        headers_completely_received = False
        environ = dict(os.environ.items())

        while True:

            recv = conn.recv(PACKET_SIZE)
            if not recv:
                conn.close()
                raise Exception('请求中断')

            if not headers_completely_received:

                headers_bytes += recv
                if b'\r\n\r\n' in headers_bytes:
                    headers_completely_received = True
                    headers_bytes, body_bytes = headers_bytes.split(b'\r\n\r\n')
                    headers_str = headers_bytes.decode()
                    first_line, *headers_key_values = headers_str.split('\r\n') # TODO first_line rename
                    request_method, path_and_query, http_protocal = first_line.split(' ')
                    if '?' in path_and_query:
                        environ['PATH_INFO'], environ['QUERY_STRING'] = path_and_query.split('?')
                    else:
                        environ['PATH_INFO'] = path_and_query
                        environ['QUERY_STRING'] =''
                    environ['SERVER_PROTOCOL'] = http_protocal
                    environ['REQUEST_METHOD'] = request_method

                    for header_kv in headers_key_values:
                        key, value = header_kv.split(': ')
                        headers[key] = value

                    if 'Content-Length' in headers:
                        content_length = int(headers['Content-Length'])
                        # 没有body或者body在当前recv中已经一起取完的情况
                        if content_length == 0 or content_length == len(body_bytes):
                            break
            else:
                body_bytes += recv
                if len(body_bytes) >= content_length:
                    break

        environ['wsgi.input'] = sys.stdin
        environ['wsgi.errors'] = sys.stderr
        environ['wsgi.version'] = (1, 0)
        environ['wsgi.multithread'] = False
        environ['wsgi.multiprocess'] = True
        environ['wsgi.run_once'] = True
        environ['SERVER_NAME'] = "Simple WSGI Server"
        environ['GATEWAY_INTERFACE'] = 'CGI/1.1'
        environ['SERVER_PORT'] = str(self.port)
        environ['REMOTE_HOST'] = ''
        environ['CONTENT_LENGTH'] = content_length
        environ['SCRIPT_NAME'] = ''
        if environ.get('HTTPS', 'off') in ('on', '1'):
            environ['wsgi.url_scheme'] = 'https'
        else:
            environ['wsgi.url_scheme'] = 'http'

        results = self.app(environ, self.start_response)
        resp_headers_str = resp_body_str = ''
        resp_headers_str += f'Status: {self.response.status}\r\n'
        for header_key, header_value in self.response.response_headers:
            resp_headers_str += f'{header_key}: {header_value}\r\n'
        resp_headers_str += f'\r\n'
        for result in results:
            resp_body_str += result.decode()
        response = resp_headers_str + resp_body_str
        self.clear_wsgi_response()

        conn.sendall(response.encode())
        conn.close()

    def clear_wsgi_response(self):
        del self.response.status
        del self.response.response_headers

    def start_response(self, status, response_headers):
        self.response.status = status
        self.response.response_headers = response_headers


if __name__ == '__main__':

    from flask import  Flask
    app = Flask(__name__)
    @app.route('/')
    def hello():
        return 'hello'

    WebServer(app=app).start()
    print("Press Ctrl+C to shut down server.")
