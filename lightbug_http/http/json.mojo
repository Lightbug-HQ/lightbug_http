from emberjson import (
    parse,
    to_string,
    serialize,
    deserialize,
    try_deserialize,
    JSON,
    JsonSerializable,
    JsonDeserializable,
)
from lightbug_http.header import Header, HeaderKey, Headers
from lightbug_http.http.common_response import OK
from lightbug_http.http.response import HTTPResponse
from lightbug_http.http.request import HTTPRequest


fn JsonOK(body: String) -> HTTPResponse:
    """Return a 200 OK response with JSON content type.

    Args:
        body: A pre-serialized JSON string.
    """
    return OK(body, "application/json")


fn JsonOK[T: JsonSerializable](value: T) -> HTTPResponse:
    """Return a 200 OK response, serializing the value to JSON.

    Parameters:
        T: A type that implements JsonSerializable.

    Args:
        value: The value to serialize to JSON.
    """
    return OK(serialize(value), "application/json")


fn json_decode(req: HTTPRequest) raises -> JSON:
    """Parse the request body as untyped JSON.

    Args:
        req: The HTTP request to extract JSON from.

    Returns:
        A parsed JSON value.

    Raises:
        An error if the body is not valid JSON.
    """
    return parse(req.get_body())


fn json_decode[T: JsonDeserializable](req: HTTPRequest) raises -> T:
    """Deserialize the request body into a typed struct.

    Parameters:
        T: A type that implements JsonDeserializable (must also be Defaultable).

    Args:
        req: The HTTP request to deserialize JSON from.

    Returns:
        The deserialized value.

    Raises:
        An error if the body is not valid JSON or doesn't match the expected schema.
    """
    return deserialize[T](String(req.get_body()))


fn JsonError(message: String) -> HTTPResponse:
    """Return a 400 Bad Request response with a JSON error body.

    Args:
        message: The error message to include.
    """
    return HTTPResponse(
        String('{"error": "', message, '"}').as_bytes(),
        headers=Headers(Header(HeaderKey.CONTENT_TYPE, "application/json")),
        status_code=400,
        status_text="Bad Request",
    )
