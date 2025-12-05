from lightbug_http.address import Addr, TCPAddr
from lightbug_http.client import Client
from lightbug_http.connection import Connection, Listener
from lightbug_http.error import ErrorHandler
from lightbug_http.header import Header, Headers
from lightbug_http.io.bytes import Bytes, bytes
from lightbug_http.server import ServerTrait
from lightbug_http.service import OK, HTTPService
from lightbug_http.uri import URI
from python import Python, PythonObject

from lightbug_http.http import HTTPRequest, HTTPResponse


comptime default_server_conn_string = "http://localhost:8080"

comptime defaultExpectedGetResponse = bytes(
    "HTTP/1.1 200 OK\r\nServer: lightbug_http\r\nContent-Type:"
    " text/plain\r\nContent-Length: 12\r\nConnection: close\r\nDate:"
    " \r\n\r\nHello world!"
)


@parameter
fn new_httpx_client() -> PythonObject:
    try:
        var httpx = Python.import_module("httpx")
        return httpx
    except e:
        print("Could not set up httpx client: " + e.__str__())
        return None


fn new_fake_listener(request_count: Int, request: Bytes) -> FakeListener:
    return FakeListener(request_count, request)


struct ReqInfo:
    var full_uri: URI
    var host: String
    var is_tls: Bool

    fn __init__(out self, full_uri: URI, host: String, is_tls: Bool):
        self.full_uri = full_uri
        self.host = host
        self.is_tls = is_tls


struct FakeClient(Client):
    """FakeClient doesn't actually send any requests, but it extracts useful information from the input.
    """

    var name: String
    var host: StringLiteral
    var port: Int
    var req_full_uri: URI
    var req_host: String
    var req_is_tls: Bool

    fn __init__(out self) raises:
        self.host = "127.0.0.1"
        self.port = 8888
        self.name = "lightbug_http_fake_client"
        self.req_full_uri = URI("")
        self.req_host = ""
        self.req_is_tls = False

    fn __init__(out self, host: StringLiteral, port: Int) raises:
        self.host = host
        self.port = port
        self.name = "lightbug_http_fake_client"
        self.req_full_uri = URI("")
        self.req_host = ""
        self.req_is_tls = False

    fn do(self, owned req: HTTPRequest) raises -> HTTPResponse:
        return OK(String(defaultExpectedGetResponse))

    fn extract(mut self, req: HTTPRequest) raises -> ReqInfo:
        var full_uri = req.uri()
        try:
            _ = full_uri.parse()
        except e:
            print("error parsing uri: " + e.__str__())

        self.req_full_uri = full_uri

        var host = String(full_uri.host())

        if host == "":
            raise Error("URI host is nil")

        self.req_host = host

        var is_tls = full_uri.is_https()
        self.req_is_tls = is_tls

        return ReqInfo(full_uri, host, is_tls)


struct FakeServer(ServerTrait):
    var __listener: FakeListener
    var __handler: FakeResponder

    fn __init__(out self, listener: FakeListener, handler: FakeResponder):
        self.__listener = listener
        self.__handler = handler

    fn __init__(
        mut self,
        addr: String,
        service: HTTPService,
        error_handler: ErrorHandler,
    ):
        self.__listener = FakeListener()
        self.__handler = FakeResponder()

    fn get_concurrency(self) -> Int:
        return 1

    fn listen_and_serve(
        self, address: String, handler: HTTPService
    ) raises -> None:
        ...

    fn serve(mut self) -> None:
        while not self.__listener.closed:
            try:
                _ = self.__listener.accept()
            except e:
                print(e)

    fn serve(self, ln: Listener, handler: HTTPService) raises -> None:
        ...


@fieldwise_init
struct FakeResponder(HTTPService):
    fn func(mut self, req: HTTPRequest) raises -> HTTPResponse:
        var method = req.method
        if method != "GET":
            raise Error("Did not expect a non-GET request! Got: " + method)
        return OK(bytes("Hello, world!"))


@fieldwise_init
struct FakeConnection(Connection):
    fn __init__(out self, laddr: String, raddr: String) raises:
        ...

    fn __init__(out self, laddr: TCPAddr, raddr: TCPAddr) raises:
        ...

    fn read(self, mut buf: Bytes) raises -> Int:
        return 0

    fn write(self, buf: Bytes) raises -> Int:
        return 0

    fn close(self) raises:
        ...

    fn local_addr(mut self) raises -> TCPAddr:
        return TCPAddr()

    fn remote_addr(self) raises -> TCPAddr:
        return TCPAddr()


@fieldwise_init
struct FakeListener:
    var request_count: Int
    var request: Bytes
    var closed: Bool

    fn __init__(out self):
        self.request_count = 0
        self.request = Bytes()
        self.closed = False

    fn __init__(out self, addr: TCPAddr):
        self.request_count = 0
        self.request = Bytes()
        self.closed = False

    fn __init__(out self, request_count: Int, request: Bytes):
        self.request_count = request_count
        self.request = request
        self.closed = False

    @always_inline
    fn accept(self) raises -> FakeConnection:
        return FakeConnection()

    fn close(self) raises:
        pass

    fn addr(self) -> TCPAddr:
        return TCPAddr()


@fieldwise_init
struct TestStruct:
    var a: String
    var b: String
    var c: Bytes
    var d: Int
    var e: TestStructNested

    fn __init__(out self, a: String, b: String) -> None:
        self.a = a
        self.b = b
        self.c = bytes("c")
        self.d = 1
        self.e = TestStructNested("a", 1)

    fn set_a_direct(mut self, a: String) -> Self:
        self.a = a
        return self

    fn set_a_copy(self, a: String) -> Self:
        return Self(a, self.b)


@fieldwise_init
struct TestStructNested:
    var a: String
    var b: Int

    fn __init__(out self, a: String, b: Int) -> None:
        self.a = a
        self.b = b

    fn set_a_direct(mut self, a: String) -> Self:
        self.a = a
        return self

    fn set_a_copy(self, a: String) -> Self:
        return Self(a, self.b)
