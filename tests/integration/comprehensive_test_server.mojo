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
struct ComprehensiveHTTP11Service(HTTPService):
    """
    Comprehensive HTTP/1.1 test server that exercises all major HTTP features
    to trigger as many httplint validation checks as possible.

    This server implements various endpoints to test:
    - All common status codes (2xx, 3xx, 4xx, 5xx)
    - Various response headers (caching, security, content negotiation)
    - Content encoding and transfer mechanisms
    - Authentication and authorization flows
    - CORS and security policies
    - Conditional requests and validation
    - Range requests
    - Error handling
    """

    fn func(mut self, req: HTTPRequest) raises -> HTTPResponse:
        var p = req.uri.path

        # ====================================================================
        # BASIC RESPONSES (2xx)
        # ====================================================================

        if p == "/":
            # Basic OK response with comprehensive headers
            return HTTPResponse(
                "Hello from Lightbug HTTP/1.1 Compliance Server".as_bytes(),
                headers=Headers(
                    Header(HeaderKey.CONTENT_TYPE, "text/plain; charset=utf-8"),
                    Header(HeaderKey.CACHE_CONTROL, "public, max-age=3600, must-revalidate"),
                    Header(HeaderKey.ETAG, '"abc123-v1"'),
                    Header(HeaderKey.LAST_MODIFIED, "Wed, 01 Jan 2025 00:00:00 GMT"),
                    Header(HeaderKey.VARY, "Accept-Encoding, Accept-Language"),
                    Header(HeaderKey.SERVER, "lightbug_http/1.0"),
                ),
                status_code=StatusCode.OK,
            )

        elif p == "/no-cache":
            # Response with no-cache directive
            return HTTPResponse(
                "This content should not be cached".as_bytes(),
                headers=Headers(
                    Header(HeaderKey.CACHE_CONTROL, "no-cache, no-store, must-revalidate"),
                    Header(HeaderKey.PRAGMA, "no-cache"),
                    Header(HeaderKey.EXPIRES, "0"),
                ),
                status_code=StatusCode.OK,
            )

        elif p == "/private":
            # Private cache-control
            return HTTPResponse(
                "Private content".as_bytes(),
                headers=Headers(
                    Header(HeaderKey.CACHE_CONTROL, "private, max-age=300"),
                ),
                status_code=StatusCode.OK,
            )

        elif p == "/created":
            # 201 Created with Location header
            return HTTPResponse(
                "Resource created".as_bytes(),
                headers=Headers(
                    Header(HeaderKey.LOCATION, "/resources/123"),
                    Header(HeaderKey.CONTENT_TYPE, "text/plain"),
                ),
                status_code=StatusCode.CREATED,
            )

        elif p == "/accepted":
            # 202 Accepted
            return HTTPResponse(
                "Request accepted for processing".as_bytes(),
                headers=Headers(
                    Header(HeaderKey.CONTENT_TYPE, "text/plain"),
                ),
                status_code=StatusCode.ACCEPTED,
            )

        elif p == "/no-content":
            # 204 No Content
            return HTTPResponse(
                "".as_bytes(),
                headers=Headers(),
                status_code=StatusCode.NO_CONTENT,
            )

        # ====================================================================
        # REDIRECTS (3xx)
        # ====================================================================

        elif p == "/redirect":
            # 301 Permanent Redirect
            return HTTPResponse(
                "Moved permanently".as_bytes(),
                headers=Headers(
                    Header(HeaderKey.LOCATION, "/redirect-target"),
                    Header(HeaderKey.CACHE_CONTROL, "max-age=86400"),
                ),
                status_code=StatusCode.MOVED_PERMANENTLY,
            )

        elif p == "/temp-redirect":
            # 302 Found (Temporary Redirect)
            return HTTPResponse(
                "Found".as_bytes(),
                headers=Headers(
                    Header(HeaderKey.LOCATION, "/redirect-target"),
                ),
                status_code=StatusCode.FOUND,
            )

        elif p == "/see-other":
            # 303 See Other
            return HTTPResponse(
                "See other".as_bytes(),
                headers=Headers(
                    Header(HeaderKey.LOCATION, "/redirect-target"),
                ),
                status_code=StatusCode.SEE_OTHER,
            )

        elif p == "/not-modified":
            # 304 Not Modified (conditional request)
            return HTTPResponse(
                "".as_bytes(),
                headers=Headers(
                    Header(HeaderKey.ETAG, '"abc123"'),
                    Header(HeaderKey.CACHE_CONTROL, "max-age=3600"),
                ),
                status_code=StatusCode.NOT_MODIFIED,
            )

        elif p == "/temp-redirect-307":
            # 307 Temporary Redirect
            return HTTPResponse(
                "Temporary redirect".as_bytes(),
                headers=Headers(
                    Header(HeaderKey.LOCATION, "/redirect-target"),
                ),
                status_code=StatusCode.TEMPORARY_REDIRECT,
            )

        elif p == "/permanent-redirect-308":
            # 308 Permanent Redirect
            return HTTPResponse(
                "Permanent redirect".as_bytes(),
                headers=Headers(
                    Header(HeaderKey.LOCATION, "/redirect-target"),
                ),
                status_code=StatusCode.PERMANENT_REDIRECT,
            )

        elif p == "/redirect-target":
            return OK("You've been redirected here!")

        # ====================================================================
        # CLIENT ERRORS (4xx)
        # ====================================================================

        elif p == "/bad-request":
            # 400 Bad Request
            return HTTPResponse(
                "Bad request".as_bytes(),
                headers=Headers(
                    Header(HeaderKey.CONTENT_TYPE, "text/plain"),
                ),
                status_code=StatusCode.BAD_REQUEST,
            )

        elif p == "/unauthorized":
            # 401 Unauthorized with WWW-Authenticate
            return HTTPResponse(
                "Authentication required".as_bytes(),
                headers=Headers(
                    Header(HeaderKey.WWW_AUTHENTICATE, 'Basic realm="Test Realm"'),
                    Header(HeaderKey.CONTENT_TYPE, "text/plain"),
                ),
                status_code=StatusCode.UNAUTHORIZED,
            )

        elif p == "/forbidden":
            # 403 Forbidden
            return HTTPResponse(
                "Access forbidden".as_bytes(),
                headers=Headers(
                    Header(HeaderKey.CONTENT_TYPE, "text/plain"),
                ),
                status_code=StatusCode.FORBIDDEN,
            )

        elif p == "/not-found":
            # 404 Not Found
            return HTTPResponse(
                "Resource not found".as_bytes(),
                headers=Headers(
                    Header(HeaderKey.CONTENT_TYPE, "text/plain"),
                ),
                status_code=StatusCode.NOT_FOUND,
            )

        elif p == "/method-not-allowed":
            # 405 Method Not Allowed
            return HTTPResponse(
                "Method not allowed".as_bytes(),
                headers=Headers(
                    Header(HeaderKey.ALLOW, "GET, HEAD, OPTIONS"),
                    Header(HeaderKey.CONTENT_TYPE, "text/plain"),
                ),
                status_code=StatusCode.METHOD_NOT_ALLOWED,
            )

        elif p == "/not-acceptable":
            # 406 Not Acceptable
            return HTTPResponse(
                "Not acceptable".as_bytes(),
                headers=Headers(
                    Header(HeaderKey.CONTENT_TYPE, "text/plain"),
                ),
                status_code=StatusCode.NOT_ACCEPTABLE,
            )

        elif p == "/conflict":
            # 409 Conflict
            return HTTPResponse(
                "Conflict".as_bytes(),
                headers=Headers(
                    Header(HeaderKey.CONTENT_TYPE, "text/plain"),
                ),
                status_code=StatusCode.CONFLICT,
            )

        elif p == "/gone":
            # 410 Gone
            return HTTPResponse(
                "Resource gone".as_bytes(),
                headers=Headers(
                    Header(HeaderKey.CONTENT_TYPE, "text/plain"),
                ),
                status_code=StatusCode.GONE,
            )

        elif p == "/precondition-failed":
            # 412 Precondition Failed
            return HTTPResponse(
                "Precondition failed".as_bytes(),
                headers=Headers(
                    Header(HeaderKey.CONTENT_TYPE, "text/plain"),
                ),
                status_code=StatusCode.PRECONDITION_FAILED,
            )

        elif p == "/payload-too-large":
            # 413 Payload Too Large
            return HTTPResponse(
                "Payload too large".as_bytes(),
                headers=Headers(
                    Header(HeaderKey.CONTENT_TYPE, "text/plain"),
                    Header("Retry-After", "3600"),
                ),
                status_code=StatusCode.REQUEST_ENTITY_TOO_LARGE,
            )

        elif p == "/uri-too-long":
            # 414 URI Too Long
            return HTTPResponse(
                "URI too long".as_bytes(),
                headers=Headers(
                    Header(HeaderKey.CONTENT_TYPE, "text/plain"),
                ),
                status_code=StatusCode.REQUEST_URI_TOO_LONG,
            )

        elif p == "/unsupported-media-type":
            # 415 Unsupported Media Type
            return HTTPResponse(
                "Unsupported media type".as_bytes(),
                headers=Headers(
                    Header(HeaderKey.CONTENT_TYPE, "text/plain"),
                    Header(HeaderKey.ACCEPT, "application/json, application/xml"),
                ),
                status_code=StatusCode.UNSUPPORTED_MEDIA_TYPE,
            )

        elif p == "/range-not-satisfiable":
            # 416 Range Not Satisfiable
            return HTTPResponse(
                "Range not satisfiable".as_bytes(),
                headers=Headers(
                    Header(HeaderKey.CONTENT_TYPE, "text/plain"),
                    Header("Content-Range", "bytes */1000"),
                ),
                status_code=StatusCode.REQUESTED_RANGE_NOT_SATISFIABLE,
            )

        elif p == "/teapot":
            # 418 I'm a teapot (for fun!)
            return HTTPResponse(
                "I'm a teapot".as_bytes(),
                headers=Headers(
                    Header(HeaderKey.CONTENT_TYPE, "text/plain"),
                ),
                status_code=StatusCode.IM_A_TEAPOT,
            )

        elif p == "/too-many-requests":
            # 429 Too Many Requests
            return HTTPResponse(
                "Too many requests".as_bytes(),
                headers=Headers(
                    Header(HeaderKey.CONTENT_TYPE, "text/plain"),
                    Header("Retry-After", "60"),
                ),
                status_code=StatusCode.TOO_MANY_REQUESTS,
            )

        # ====================================================================
        # SERVER ERRORS (5xx)
        # ====================================================================

        elif p == "/internal-error":
            # 500 Internal Server Error
            return HTTPResponse(
                "Internal server error".as_bytes(),
                headers=Headers(
                    Header(HeaderKey.CONTENT_TYPE, "text/plain"),
                ),
                status_code=StatusCode.INTERNAL_SERVER_ERROR,
            )

        elif p == "/not-implemented":
            # 501 Not Implemented
            return HTTPResponse(
                "Not implemented".as_bytes(),
                headers=Headers(
                    Header(HeaderKey.CONTENT_TYPE, "text/plain"),
                ),
                status_code=StatusCode.NOT_IMPLEMENTED,
            )

        elif p == "/bad-gateway":
            # 502 Bad Gateway
            return HTTPResponse(
                "Bad gateway".as_bytes(),
                headers=Headers(
                    Header(HeaderKey.CONTENT_TYPE, "text/plain"),
                ),
                status_code=StatusCode.BAD_GATEWAY,
            )

        elif p == "/service-unavailable":
            # 503 Service Unavailable
            return HTTPResponse(
                "Service unavailable".as_bytes(),
                headers=Headers(
                    Header(HeaderKey.CONTENT_TYPE, "text/plain"),
                    Header("Retry-After", "120"),
                ),
                status_code=StatusCode.SERVICE_UNAVAILABLE,
            )

        elif p == "/gateway-timeout":
            # 504 Gateway Timeout
            return HTTPResponse(
                "Gateway timeout".as_bytes(),
                headers=Headers(
                    Header(HeaderKey.CONTENT_TYPE, "text/plain"),
                ),
                status_code=StatusCode.GATEWAY_TIMEOUT,
            )

        # ====================================================================
        # SECURITY HEADERS
        # ====================================================================

        elif p == "/security-headers":
            # Response with comprehensive security headers
            return HTTPResponse(
                "Secure content".as_bytes(),
                headers=Headers(
                    Header(HeaderKey.CONTENT_TYPE, "text/html; charset=utf-8"),
                    Header("X-Content-Type-Options", "nosniff"),
                    Header("X-Frame-Options", "DENY"),
                    Header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'"),
                    Header("Referrer-Policy", "strict-origin-when-cross-origin"),
                    Header("Cross-Origin-Opener-Policy", "same-origin"),
                    Header("Cross-Origin-Embedder-Policy", "require-corp"),
                    Header("Cross-Origin-Resource-Policy", "same-origin"),
                ),
                status_code=StatusCode.OK,
            )

        # ====================================================================
        # CORS HEADERS
        # ====================================================================

        elif p == "/cors":
            # CORS headers
            return HTTPResponse(
                "CORS enabled".as_bytes(),
                headers=Headers(
                    Header(HeaderKey.CONTENT_TYPE, "application/json"),
                    Header("Access-Control-Allow-Origin", "*"),
                    Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS"),
                    Header("Access-Control-Allow-Headers", "Content-Type, Authorization"),
                    Header("Access-Control-Max-Age", "3600"),
                ),
                status_code=StatusCode.OK,
            )

        elif p == "/cors-credentials":
            # CORS with credentials
            return HTTPResponse(
                "CORS with credentials".as_bytes(),
                headers=Headers(
                    Header(HeaderKey.CONTENT_TYPE, "application/json"),
                    Header("Access-Control-Allow-Origin", "https://example.com"),
                    Header("Access-Control-Allow-Credentials", "true"),
                ),
                status_code=StatusCode.OK,
            )

        # ====================================================================
        # CONTENT TYPES
        # ====================================================================

        elif p == "/json":
            return HTTPResponse(
                '{"message": "hello", "status": "ok"}'.as_bytes(),
                headers=Headers(
                    Header(HeaderKey.CONTENT_TYPE, "application/json; charset=utf-8"),
                    Header(HeaderKey.CACHE_CONTROL, "no-cache"),
                ),
                status_code=StatusCode.OK,
            )

        elif p == "/html":
            return HTTPResponse(
                "<html><body><h1>Hello World</h1></body></html>".as_bytes(),
                headers=Headers(
                    Header(HeaderKey.CONTENT_TYPE, "text/html; charset=utf-8"),
                ),
                status_code=StatusCode.OK,
            )

        elif p == "/xml":
            return HTTPResponse(
                '<?xml version="1.0"?><root><message>Hello</message></root>'.as_bytes(),
                headers=Headers(
                    Header(HeaderKey.CONTENT_TYPE, "application/xml; charset=utf-8"),
                ),
                status_code=StatusCode.OK,
            )

        # ====================================================================
        # COOKIES
        # ====================================================================

        elif p == "/set-cookie":
            return HTTPResponse(
                "Cookie set".as_bytes(),
                headers=Headers(
                    Header(HeaderKey.CONTENT_TYPE, "text/plain"),
                    Header("Set-Cookie", "session=abc123; Path=/; HttpOnly; SameSite=Strict; Max-Age=3600"),
                ),
                status_code=StatusCode.OK,
            )

        elif p == "/set-secure-cookie":
            return HTTPResponse(
                "Secure cookie set".as_bytes(),
                headers=Headers(
                    Header(HeaderKey.CONTENT_TYPE, "text/plain"),
                    Header("Set-Cookie", "__Secure-session=xyz789; Path=/; Secure; HttpOnly; SameSite=Strict"),
                ),
                status_code=StatusCode.OK,
            )

        # ====================================================================
        # CONTENT DISPOSITION
        # ====================================================================

        elif p == "/download":
            return HTTPResponse(
                "File content here".as_bytes(),
                headers=Headers(
                    Header(HeaderKey.CONTENT_TYPE, "application/octet-stream"),
                    Header("Content-Disposition", 'attachment; filename="test.txt"'),
                ),
                status_code=StatusCode.OK,
            )

        # ====================================================================
        # AGE HEADER (proxy/cache scenarios)
        # ====================================================================

        elif p == "/cached":
            return HTTPResponse(
                "Cached content".as_bytes(),
                headers=Headers(
                    Header(HeaderKey.CONTENT_TYPE, "text/plain"),
                    Header(HeaderKey.CACHE_CONTROL, "public, max-age=3600"),
                    Header("Age", "300"),
                    Header(HeaderKey.ETAG, '"cache-v1"'),
                ),
                status_code=StatusCode.OK,
            )

        # ====================================================================
        # LINK HEADER
        # ====================================================================

        elif p == "/with-links":
            return HTTPResponse(
                "Content with links".as_bytes(),
                headers=Headers(
                    Header(HeaderKey.CONTENT_TYPE, "text/html"),
                    Header("Link", '</style.css>; rel="stylesheet", </script.js>; rel="preload"; as="script"'),
                ),
                status_code=StatusCode.OK,
            )

        # Default 404
        return HTTPResponse(
            "Not found".as_bytes(),
            headers=Headers(
                Header(HeaderKey.CONTENT_TYPE, "text/plain"),
            ),
            status_code=StatusCode.NOT_FOUND,
        )


fn main() raises:
    var server = Server(tcp_keep_alive=True)
    var service = ComprehensiveHTTP11Service()
    print("🔥🐝 Comprehensive HTTP/1.1 Compliance Test Server")
    print("=" * 60)
    print("This server implements various endpoints to test HTTP/1.1 compliance")
    print("Server starting on http://127.0.0.1:8080")
    print("=" * 60)
    server.listen_and_serve("127.0.0.1:8080", service)
