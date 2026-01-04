from lightbug_http import (
    OK,
    Header,
    HeaderKey,
    Headers,
    HTTPRequest,
    HTTPResponse,
    HTTPService,
    NotFound,
    Server,
    StatusCode,
)


@fieldwise_init
struct ConformanceTestService(HTTPService):
    """HTTP service for HTTP/1.1 conformance testing.

    This service implements various endpoints to test HTTP/1.1 compliance
    as specified in RFC 9110, RFC 9112, and related specifications.
    """

    fn func(mut self, req: HTTPRequest) raises -> HTTPResponse:
        var p = req.uri.path

        # Basic endpoints
        if p == "/":
            return OK("Lightbug HTTP Conformance Test Server")

        # Echo endpoint - returns request info
        elif p == "/echo":
            var body = String("Method: ") + req.method + "\n"
            body += "Path: " + req.uri.path + "\n"
            body += "Version: HTTP/1.1\n"
            return OK(body)

        # Headers test endpoint
        elif p == "/headers":
            var custom_headers = Headers(
                Header(HeaderKey.CONTENT_TYPE, "text/plain"),
                Header(HeaderKey.CACHE_CONTROL, "no-cache"),
                Header("X-Custom-Header", "test-value"),
            )
            return HTTPResponse(
                "Header test".as_bytes(),
                headers=custom_headers,
                status_code=StatusCode.OK,
            )

        # Different status codes
        elif p == "/status/200":
            return OK("OK")
        elif p == "/status/201":
            return HTTPResponse(
                "Created".as_bytes(),
                status_code=StatusCode.CREATED,
            )
        elif p == "/status/204":
            return HTTPResponse(
                "".as_bytes(),
                status_code=StatusCode.NO_CONTENT,
            )
        elif p == "/status/301":
            return HTTPResponse(
                "Moved Permanently".as_bytes(),
                headers=Headers(Header(HeaderKey.LOCATION, "/redirect-target")),
                status_code=StatusCode.MOVED_PERMANENTLY,
            )
        elif p == "/status/400":
            return HTTPResponse(
                "Bad Request".as_bytes(),
                status_code=StatusCode.BAD_REQUEST,
            )
        elif p == "/status/404":
            return NotFound("Not Found")
        elif p == "/status/500":
            return HTTPResponse(
                "Internal Server Error".as_bytes(),
                status_code=StatusCode.INTERNAL_SERVER_ERROR,
            )

        # Content-Length test
        elif p == "/content-length":
            var body = "This is a test body with known length"
            var headers = Headers(
                Header(HeaderKey.CONTENT_TYPE, "text/plain"),
                Header(HeaderKey.CONTENT_LENGTH, String(len(body))),
            )
            return HTTPResponse(
                body.as_bytes(),
                headers=headers,
                status_code=StatusCode.OK,
            )

        # Large response
        elif p == "/large":
            var large_body = "x" * 10000  # 10KB of data
            return OK(large_body)

        # Redirect chain
        elif p == "/redirect/1":
            return HTTPResponse(
                "".as_bytes(),
                headers=Headers(Header(HeaderKey.LOCATION, "/redirect/2")),
                status_code=StatusCode.FOUND,
            )
        elif p == "/redirect/2":
            return HTTPResponse(
                "".as_bytes(),
                headers=Headers(Header(HeaderKey.LOCATION, "/redirect/final")),
                status_code=StatusCode.FOUND,
            )
        elif p == "/redirect/final":
            return OK("Redirect chain complete")

        # Connection handling
        elif p == "/close":
            return HTTPResponse(
                "Connection will close".as_bytes(),
                headers=Headers(Header(HeaderKey.CONNECTION, "close")),
                status_code=StatusCode.OK,
            )

        # Method tests
        elif p == "/methods":
            if req.method == "GET":
                return OK("GET received")
            elif req.method == "POST":
                return OK("POST received")
            elif req.method == "PUT":
                return OK("PUT received")
            elif req.method == "DELETE":
                return OK("DELETE received")
            elif req.method == "HEAD":
                return OK("")
            elif req.method == "OPTIONS":
                var headers = Headers(
                    Header("Allow", "GET, POST, PUT, DELETE, HEAD, OPTIONS"),
                )
                return HTTPResponse(
                    "".as_bytes(),
                    headers=headers,
                    status_code=StatusCode.OK,
                )
            else:
                return HTTPResponse(
                    "Method not allowed".as_bytes(),
                    status_code=StatusCode.METHOD_NOT_ALLOWED,
                )

        return NotFound(p)


fn main() raises:
    print("[INFO] Starting Lightbug HTTP Conformance Test Server")
    print("[INFO] Listening on http://127.0.0.1:8080")
    print("[INFO] Press Ctrl+C to stop")

    var server = Server(tcp_keep_alive=True)
    var service = ConformanceTestService()
    server.listen_and_serve("127.0.0.1:8080", service)
