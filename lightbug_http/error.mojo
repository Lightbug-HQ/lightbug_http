from lightbug_http.http import HTTPResponse

alias TODO_MESSAGE = "TODO".as_bytes()


# TODO: Custom error handlers provided by the user
struct ErrorHandler(Movable, Copyable, ImplicitlyCopyable):
    fn __init__(out self):
        pass

    fn Error(self) -> HTTPResponse:
        return HTTPResponse(TODO_MESSAGE)
