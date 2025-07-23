from lightbug_http.io.bytes import Bytes


fn OK(body: String, content_type: String = "text/plain") -> HTTPResponse:
    return HTTPResponse(
        headers=Headers(Header(HeaderKey.CONTENT_TYPE, content_type)),
        body_bytes=bytes(body),
    )


fn OK(body: Bytes, content_type: String = "text/plain") -> HTTPResponse:
    return HTTPResponse(
        headers=Headers(Header(HeaderKey.CONTENT_TYPE, content_type)),
        body_bytes=body,
    )


fn OK(
    body: Bytes, content_type: String, content_encoding: String
) -> HTTPResponse:
    return HTTPResponse(
        headers=Headers(
            Header(HeaderKey.CONTENT_TYPE, content_type),
            Header(HeaderKey.CONTENT_ENCODING, content_encoding),
        ),
        body_bytes=body,
    )


fn SeeOther(
    location: String, content_type: String, owned cookies: List[Cookie] = []
) -> HTTPResponse:
    return HTTPResponse(
        bytes("See Other"),
        cookies=ResponseCookieJar(cookies^),
        headers=Headers(
            Header(HeaderKey.LOCATION, location),
            Header(HeaderKey.CONTENT_TYPE, content_type),
        ),
        status_code=303,
        status_text="See Other",
    )


fn BadRequest() -> HTTPResponse:
    return HTTPResponse(
        bytes("Bad Request"),
        headers=Headers(Header(HeaderKey.CONTENT_TYPE, "text/plain")),
        status_code=400,
        status_text="Bad Request",
    )


fn NotFound(path: String) -> HTTPResponse:
    return HTTPResponse(
        body_bytes=bytes("path " + path + " not found"),
        headers=Headers(Header(HeaderKey.CONTENT_TYPE, "text/plain")),
        status_code=404,
        status_text="Not Found",
    )

fn URITooLong() -> HTTPResponse:
    return HTTPResponse(
        bytes("URI Too Long"),
        headers=Headers(Header(HeaderKey.CONTENT_TYPE, "text/plain")),
        status_code=414,
        status_text="URI Too Long"
    )


fn InternalError() -> HTTPResponse:
    return HTTPResponse(
        bytes("Failed to process request"),
        headers=Headers(Header(HeaderKey.CONTENT_TYPE, "text/plain")),
        status_code=500,
        status_text="Internal Server Error",
    )
