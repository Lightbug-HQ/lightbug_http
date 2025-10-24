from memory import Span
from benchmark import *
from lightbug_http.io.bytes import bytes, Bytes
from lightbug_http.header import Headers, Header
from lightbug_http.io.bytes import ByteReader, ByteWriter
from lightbug_http.http import HTTPRequest, HTTPResponse, encode
from lightbug_http.uri import URI
from lightbug_http.server import default_max_request_body_size, default_max_request_uri_length

alias headers = "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\nContent-Type: text/html\r\nContent-Length: 1234\r\nConnection: close\r\nTrailer: end-of-message\r\n\r\n"

alias body = "I am the body of an HTTP request" * 5
alias body_bytes = bytes(body)
alias Request = "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\nContent-Type: text/html\r\nContent-Length: 1234\r\nConnection: close\r\nTrailer: end-of-message\r\n\r\n" + body
alias Response = "HTTP/1.1 200 OK\r\nserver: lightbug_http\r\ncontent-type: application/octet-stream\r\nconnection: keep-alive\r\ncontent-length: 13\r\ndate: 2024-06-02T13:41:50.766880+00:00\r\n\r\n" + body


fn main():
    run_benchmark()


fn run_benchmark():
    try:
        var config = BenchConfig()
        config.verbose_timing = True
        var m = Bench(config.copy())
        m.bench_function[lightbug_benchmark_header_encode](BenchId("HeaderEncode"))
        m.bench_function[lightbug_benchmark_header_parse](BenchId("HeaderParse"))
        m.bench_function[lightbug_benchmark_request_encode](BenchId("RequestEncode"))
        m.bench_function[lightbug_benchmark_request_parse](BenchId("RequestParse"))
        m.bench_function[lightbug_benchmark_response_encode](BenchId("ResponseEncode"))
        m.bench_function[lightbug_benchmark_response_parse](BenchId("ResponseParse"))
        m.dump_report()
    except:
        print("failed to start benchmark")


fn get_headers_struct() -> Headers:
    return Headers(
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
        var body_data = body.as_bytes()
        var res = HTTPResponse(body_data, headers=get_headers_struct())
        _ = encode(res^)

    b.iter[response_encode]()


@parameter
fn lightbug_benchmark_response_parse(mut b: Bencher):
    @always_inline
    @parameter
    fn response_parse():
        try:
            var response_data = Response.as_bytes()
            _ = HTTPResponse.from_bytes(response_data)
        except:
            pass

    b.iter[response_parse]()


@parameter
fn lightbug_benchmark_request_parse(mut b: Bencher):
    @always_inline
    @parameter
    fn request_parse():
        try:
            var request_data = Request.as_bytes()
            _ = HTTPRequest.from_bytes("127.0.0.1/path", default_max_request_body_size, default_max_request_uri_length, request_data)
        except:
            pass

    b.iter[request_parse]()


@parameter
fn lightbug_benchmark_request_encode(mut b: Bencher):
    @always_inline
    @parameter
    fn request_encode() raises:
        var uri = URI.parse("http://127.0.0.1:8080/some-path")
        var body_data = bytes(body)
        var req = HTTPRequest(
            uri=uri,
            headers=get_headers_struct(),
            body=body_data,
        )
        _ = encode(req^)

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
        b.write(get_headers_struct())

    b.iter[header_encode]()


@parameter
fn lightbug_benchmark_header_parse(mut b: Bencher):
    @always_inline
    @parameter
    fn header_parse():
        try:
            var header = Headers()
            var headers_data = headers.as_bytes()
            var reader = ByteReader(headers_data)
            _ = header.parse_raw(reader)
        except e:
            print("failed", e)

    b.iter[header_parse]()
