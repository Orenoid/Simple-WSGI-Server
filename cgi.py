import os, sys
from flask import Flask

app = Flask(__name__)


@app.route('/')
def hello():
    return 'hello'


def run_with_cgi(application):
    environ = dict(os.environ.items())
    environ['wsgi.input'] = sys.stdin
    environ['wsgi.errors'] = sys.stderr
    environ['wsgi.version'] = (1, 0)
    environ['wsgi.multithread'] = False
    environ['wsgi.multiprocess'] = True
    environ['wsgi.run_once'] = True
    environ['SERVER_NAME'] = "server name"
    environ['GATEWAY_INTERFACE'] = 'CGI/1.1'
    environ['SERVER_PORT'] = '8500'
    environ['REMOTE_HOST'] = ''
    environ['CONTENT_LENGTH'] = ''
    environ['SCRIPT_NAME'] = ''
    environ['REQUEST_METHOD'] = 'GET'
    environ['SCRIPT_NAME'] = ''
    environ['PATH_INFO'] = '/'
    environ['QUERY_STRING'] = 'a=1'
    environ['SERVER_PROTOCOL'] = 'HTTP/1.1'

    if environ.get('HTTPS', 'off') in ('on', '1'):
        environ['wsgi.url_scheme'] = 'https'
    else:
        environ['wsgi.url_scheme'] = 'http'

    headers_set = []
    headers_sent = []

    def write(data):
        if not headers_set:
            raise AssertionError("write() before start_response()")

        elif not headers_sent:
            # 在第一次输出之前发送已存储的报头。
            status, response_headers = headers_sent[:] = headers_set
            sys.stdout.write('Status: %s\r\n' % status)
            for header_key, header_value in response_headers:
                sys.stdout.write(f'{header_key}: {header_value}\r\n')
            sys.stdout.write('\r\n')

        sys.stdout.write(data.decode())
        sys.stdout.flush()

    def start_response(status, response_headers, exc_info=None):
        if exc_info:
            try:
                if headers_sent:
                    # 如果报头已发送，则重新抛出原始的异常。
                    # raise exc_info[0], exc_info[1], exc_info[2]
                    raise Exception('headers sent')
            finally:
                exc_info = None  # 避免死循环。
        elif headers_set:
            raise AssertionError("Headers already set!")

        headers_set[:] = [status, response_headers]
        return write

    result = application(environ, start_response)
    try:
        for data in result:
            if data:  # 在报文体出现前不发送报头。
                write(data)
        if not headers_sent:
            write('')  # 如果报文体为空，则发送报头。
    finally:
        if hasattr(result, 'close'):
            result.close()


def demo_app(environ, start_response):
    from io import StringIO
    stdout = StringIO()
    print("Hello world!", file=stdout)
    print(file=stdout)
    h = sorted(environ.items())
    # for k, v in h:
    #     print(k, '=', repr(v), file=stdout)
    start_response("200 OK", [('Content-Type', 'text/plain; charset=utf-8')])
    return [stdout.getvalue().encode("utf-8")]


if __name__ == '__main__':
    # from wsgiref.simple_server import make_server
    # httpd = make_server('', 5000, demo_app)
    # httpd.serve_forever()
    run_with_cgi(demo_app)
