from lightbug_http.io.bytes import Bytes


fn OK(body: String, content_type: String = "text/plain") -> HTTPResponse:
    return HTTPResponse(
        headers=Headers(Header(HeaderKey.CONTENT_TYPE, content_type)),
        body_bytes=body.as_bytes(),
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
    location: String, content_type: String, var cookies: List[Cookie] = []
) -> HTTPResponse:
    return HTTPResponse(
        "See Other".as_bytes(),
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
        "Bad Request".as_bytes(),
        headers=Headers(Header(HeaderKey.CONTENT_TYPE, "text/plain")),
        status_code=400,
        status_text="Bad Request",
    )


fn BadRequest(message: String) -> HTTPResponse:
    """Bad Request with a specific error message.

    Args:
        message: Specific explanation of what went wrong with the request.
    """
    return HTTPResponse(
        String("Bad Request: ", message).as_bytes(),
        headers=Headers(Header(HeaderKey.CONTENT_TYPE, "text/plain")),
        status_code=400,
        status_text="Bad Request",
    )


fn NotFound(path: String) -> HTTPResponse:
    return HTTPResponse(
        body_bytes=String("path ", path, " not found").as_bytes(),
        headers=Headers(Header(HeaderKey.CONTENT_TYPE, "text/plain")),
        status_code=404,
        status_text="Not Found",
    )


fn PayloadTooLarge() -> HTTPResponse:
    return HTTPResponse(
        "Payload Too Large".as_bytes(),
        headers=Headers(Header(HeaderKey.CONTENT_TYPE, "text/plain")),
        status_code=413,
        status_text="Payload Too Large",
    )


fn URITooLong() -> HTTPResponse:
    return HTTPResponse(
        "URI Too Long".as_bytes(),
        headers=Headers(Header(HeaderKey.CONTENT_TYPE, "text/plain")),
        status_code=414,
        status_text="URI Too Long",
    )


fn InternalError() -> HTTPResponse:
    return HTTPResponse(
        "Failed to process request".as_bytes(),
        headers=Headers(Header(HeaderKey.CONTENT_TYPE, "text/plain")),
        status_code=500,
        status_text="Internal Server Error",
    )
