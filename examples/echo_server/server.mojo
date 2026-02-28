from lightbug_http import OK, HTTPRequest, HTTPResponse, HTTPService, Server


@fieldwise_init
struct EchoService(HTTPService):
    fn func(mut self, req: HTTPRequest) raises -> HTTPResponse:
        var content_type = req.headers.get("content-type")
        return OK(req.body_raw, content_type.or_else("text/plain; charset=utf-8"))


fn main() raises:
    var server = Server()
    var handler = EchoService()
    server.listen_and_serve("localhost:8080", handler)
