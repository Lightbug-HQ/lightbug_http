from lightbug_http.header import Header, Headers, parse_request_headers
from lightbug_http.io.bytes import ByteReader, Bytes, ByteWriter
from lightbug_http.uri import URI
from memory import Span

from benchmark import *
from lightbug_http.http import HTTPRequest, HTTPResponse, encode

# Constants from ServerConfig defaults
comptime default_max_request_body_size = 4 * 1024 * 1024  # 4MB
comptime default_max_request_uri_length = 8192


comptime headers = "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\nContent-Type: text/html\r\nContent-Length: 1234\r\nConnection: close\r\nTrailer: end-of-message\r\n\r\n"

comptime body = "I am the body of an HTTP request" * 5
comptime body_bytes = body.as_bytes()
comptime Request = "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\nContent-Type: text/html\r\nContent-Length: 1234\r\nConnection: close\r\nTrailer: end-of-message\r\n\r\n" + body
comptime Response = "HTTP/1.1 200 OK\r\nserver: lightbug_http\r\ncontent-type: application/octet-stream\r\nconnection: keep-alive\r\ncontent-length: 13\r\ndate: 2024-06-02T13:41:50.766880+00:00\r\n\r\n" + body


fn main():
    run_benchmark()


fn run_benchmark():
    try:
        var config = BenchConfig()
        config.verbose_timing = True
        var m = Bench(config^)
        m.bench_function[lightbug_benchmark_header_encode](
            BenchId("HeaderEncode")
        )
        m.bench_function[lightbug_benchmark_header_parse](
            BenchId("HeaderParse")
        )
        m.bench_function[lightbug_benchmark_request_encode](
            BenchId("RequestEncode")
        )
        m.bench_function[lightbug_benchmark_request_parse](
            BenchId("RequestParse")
        )
        m.bench_function[lightbug_benchmark_response_encode](
            BenchId("ResponseEncode")
        )
        m.bench_function[lightbug_benchmark_response_parse](
            BenchId("ResponseParse")
        )
        m.dump_report()
    except:
        print("failed to start benchmark")


comptime headers_struct = Headers(
    Header("Content-Type", "application/json"),
    Header("Content-Length", "1234"),
    Header("Connection", "close"),
    Header("Date", "some-datetime"),
    Header("SomeHeader", "SomeValue"),
)


@parameter
fn lightbug_benchmark_response_encode(mut b: Bencher):
    @always_inline
    @parameter
    fn response_encode():
        var res = HTTPResponse(
            body.as_bytes(), headers=materialize[headers_struct]()
        )
        _ = encode(res^)

    b.iter[response_encode]()


@parameter
fn lightbug_benchmark_response_parse(mut b: Bencher):
    @always_inline
    @parameter
    fn response_parse():
        try:
            _ = HTTPResponse.from_bytes(Response.as_bytes())
        except:
            pass

    b.iter[response_parse]()


@parameter
fn lightbug_benchmark_request_parse(mut b: Bencher):
    @always_inline
    @parameter
    fn request_parse():
        try:
            var parsed = parse_request_headers(Span(Request.as_bytes()))
            try:
                _ = HTTPRequest.from_parsed(
                    "127.0.0.1/path",
                    parsed^,
                    Bytes(),  # body is separate in new API
                    default_max_request_uri_length,
                )
            except:
                pass
        except:
            pass

    b.iter[request_parse]()


@parameter
fn lightbug_benchmark_request_encode(mut b: Bencher):
    @always_inline
    @parameter
    fn request_encode() raises:
        try:
            var req = HTTPRequest(
                uri=URI.parse("http://127.0.0.1:8080/some-path"),
                headers=materialize[headers_struct](),
                body=List[Byte](materialize[body_bytes]()),
            )
            _ = encode(req^)
        except e:
            print("failed to encode request, error: ", e)
            raise Error("failed to encode request")

    try:
        b.iter[request_encode]()
    except e:
        print("failed to encode request, error: ", e)


@parameter
fn lightbug_benchmark_header_encode(mut b: Bencher):
    @always_inline
    @parameter
    fn header_encode():
        var b = ByteWriter()
        b.write(materialize[headers_struct]())

    b.iter[header_encode]()


@parameter
fn lightbug_benchmark_header_parse(mut b: Bencher):
    @always_inline
    @parameter
    fn header_parse():
        try:
            _ = parse_request_headers(Span(headers.as_bytes()))
        except e:
            print("failed", e)

    b.iter[header_parse]()
