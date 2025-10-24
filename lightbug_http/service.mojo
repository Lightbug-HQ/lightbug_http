from lightbug_http.http import HTTPRequest, HTTPResponse, OK, NotFound
from lightbug_http.io.bytes import Bytes, bytes
from lightbug_http.strings import to_string
from lightbug_http.header import HeaderKey


trait HTTPService:
    fn func(mut self, req: HTTPRequest) raises -> HTTPResponse:
        ...


@fieldwise_init
struct Printer(HTTPService):
    fn func(mut self, req: HTTPRequest) raises -> HTTPResponse:
        print("Request URI:", req.uri.request_uri)
        print("Request protocol:", req.protocol)
        print("Request method:", req.method)
        if HeaderKey.CONTENT_TYPE in req.headers:
            print("Request Content-Type:", req.headers[HeaderKey.CONTENT_TYPE])
        if req.body_raw:
            print("Request Body:", to_string(req.body_raw.copy()))

        return OK(req.body_raw)


@fieldwise_init
struct Welcome(HTTPService):
    fn func(mut self, req: HTTPRequest) raises -> HTTPResponse:
        if req.uri.path == "/":
            with open("static/lightbug_welcome.html", "r") as f:
                return OK(Bytes(f.read_bytes()), "text/html; charset=utf-8")

        if req.uri.path == "/logo.png":
            with open("static/logo.png", "r") as f:
                return OK(Bytes(f.read_bytes()), "image/png")

        return NotFound(req.uri.path)


@fieldwise_init
struct ExampleRouter(HTTPService):
    fn func(mut self, req: HTTPRequest) raises -> HTTPResponse:
        if req.uri.path == "/":
            print("I'm on the index path!")
        if req.uri.path == "/first":
            print("I'm on /first!")
        elif req.uri.path == "/second":
            print("I'm on /second!")
        elif req.uri.path == "/echo":
            print(to_string(req.body_raw.copy()))

        return OK(req.body_raw)


@fieldwise_init
struct TechEmpowerRouter(HTTPService):
    fn func(mut self, req: HTTPRequest) raises -> HTTPResponse:
        if req.uri.path == "/plaintext":
            return OK("Hello, World!", "text/plain")
        elif req.uri.path == "/json":
            return OK('{"message": "Hello, World!"}', "application/json")

        return OK("Hello world!")  # text/plain is the default


@fieldwise_init
struct Counter(HTTPService):
    var counter: Int

    fn __init__(out self):
        self.counter = 0

    fn func(mut self, req: HTTPRequest) raises -> HTTPResponse:
        self.counter += 1
        return OK("I have been called: " + String(self.counter) + " times")
