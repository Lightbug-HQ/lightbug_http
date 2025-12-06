from lightbug_http.http import HTTPResponse


comptime TODO_MESSAGE = "TODO".as_bytes()


# TODO: Custom error handlers provided by the user
@fieldwise_init
struct ErrorHandler(Copyable):
    fn Error(self) -> HTTPResponse:
        return HTTPResponse(TODO_MESSAGE)
