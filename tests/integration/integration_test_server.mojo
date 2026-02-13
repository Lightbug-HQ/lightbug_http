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
struct IntegrationTestService(HTTPService):
    fn func(mut self, req: HTTPRequest) raises -> HTTPResponse:
        var p = req.uri.path
        if p == "/":
            return OK("hello")
        elif p == "/redirect":
            return HTTPResponse(
                "get off my lawn".as_bytes(),
                headers=Headers(Header(HeaderKey.LOCATION, "/rd-destination")),
                status_code=StatusCode.PERMANENT_REDIRECT,
            )
        elif p == "/rd-destination":
            return OK("yay you made it")
        elif p == "/close-connection":
            return OK("connection closed")
        elif p == "/large-headers":
            return OK("alright")
        elif p == "/error":
            raise Error("oops")

        return NotFound("wrong")


fn main() raises:
    var server = Server()
    var service = IntegrationTestService()
    server.listen_and_serve("127.0.0.1:8080", service)
