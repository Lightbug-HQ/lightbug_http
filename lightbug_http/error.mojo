from lightbug_http.http import HTTPResponse

alias TODO_MESSAGE = "TODO".as_bytes()


# TODO: Custom error handlers provided by the user
@fieldwise_init
struct ErrorHandler(Copyable, Movable):
    fn Error(self) -> HTTPResponse:
        return HTTPResponse(TODO_MESSAGE)
