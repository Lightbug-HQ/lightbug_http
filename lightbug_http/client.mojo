from collections import Dict
from lightbug_http.connection import TCPConnection, default_buffer_size, create_connection
from lightbug_http.http import HTTPRequest, HTTPResponse, encode
from lightbug_http.header import Headers, HeaderKey
from lightbug_http.io.bytes import Bytes, ByteReader
from lightbug_http._logger import logger
from lightbug_http.pool_manager import PoolManager, PoolKey
from lightbug_http.uri import URI, Scheme


struct Client:
    var host: String
    var port: Int
    var name: String
    var allow_redirects: Bool

    var _connections: PoolManager[TCPConnection]

    fn __init__(
        out self,
        host: String = "127.0.0.1",
        port: Int = 8888,
        cached_connections: Int = 10,
        allow_redirects: Bool = False,
    ):
        self.host = host
        self.port = port
        self.name = "lightbug_http_client"
        self.allow_redirects = allow_redirects
        self._connections = PoolManager[TCPConnection](cached_connections)

    fn do(mut self, var request: HTTPRequest) raises -> HTTPResponse:
        """The `do` method is responsible for sending an HTTP request to a server and receiving the corresponding response.

        It performs the following steps:
        1. Creates a connection to the server specified in the request.
        2. Sends the request body using the connection.
        3. Receives the response from the server.
        4. Closes the connection.
        5. Returns the received response as an `HTTPResponse` object.

        Note: The code assumes that the `HTTPRequest` object passed as an argument has a valid URI with a host and port specified.

        Args:
            request: An `HTTPRequest` object representing the request to be sent.

        Returns:
            The received response.

        Raises:
            Error: If there is a failure in sending or receiving the message.
        """
        if request.uri.host == "":
            raise Error("Client.do: Host must not be empty.")

        # TODO (@thatstoasty): Implement TLS support.
        # var is_tls = False
        var scheme = materialize[Scheme.HTTP]()
        if request.uri.is_https():
            # is_tls = True
            scheme = materialize[Scheme.HTTPS]()

        var port: UInt16
        if request.uri.port:
            port = request.uri.port.value()
        else:
            if request.uri.scheme == Scheme.HTTP.value:
                port = 80
            elif request.uri.scheme == Scheme.HTTPS.value:
                port = 443
            else:
                raise Error("Client.do: Invalid scheme received in the URI.")

        var pool_key = PoolKey(request.uri.host, port, scheme^)
        var cached_connection = False
        var conn: TCPConnection
        try:
            conn = self._connections.take(pool_key)
            cached_connection = True
        except e:
            if String(e) == "PoolManager.take: Key not found.":
                conn = create_connection(request.uri.host, port)
            else:
                logger.error(e)
                raise Error("Client.do: Failed to create a connection to host.")

        try:
            _ = conn.write(encode(request.copy()))
        except e:
            # Maybe peer reset ungracefully, so try a fresh connection
            if String(e) == "SendError: Connection reset by peer.":
                logger.debug("Client.do: Connection reset by peer. Trying a fresh connection.")
                conn.teardown()
                if cached_connection:
                    return self.do(request^)
            logger.error("Client.do: Failed to send message.")
            raise e

        # TODO: What if the response is too large for the buffer? We should read until the end of the response. (@thatstoasty)
        var new_buf = Bytes(capacity=default_buffer_size)
        try:
            _ = conn.read(new_buf)
        except e:
            if String(e) == "EOF":
                conn.teardown()
                if cached_connection:
                    return self.do(request^)
                raise Error("Client.do: No response received from the server.")
            else:
                logger.error(e)
                raise Error("Client.do: Failed to read response from peer.")

        var response: HTTPResponse
        try:
            response = HTTPResponse.from_bytes(new_buf, conn)
        except e:
            logger.error("Failed to parse a response...")
            try:
                conn.teardown()
            except:
                logger.error("Failed to teardown connection...")
            raise e

        # Redirects should not keep the connection alive, as redirects can send the client to a different server.
        if self.allow_redirects and response.is_redirect():
            conn.teardown()
            return self._handle_redirect(request^, response^)
        # Server told the client to close the connection, we can assume the server closed their side after sending the response.
        elif response.connection_close():
            conn.teardown()
        # Otherwise, persist the connection by giving it back to the pool manager.
        else:
            self._connections.give(pool_key, conn^)
        return response^

    fn _handle_redirect(
        mut self, var original_request: HTTPRequest, var original_response: HTTPResponse
    ) raises -> HTTPResponse:
        var new_uri: URI
        var new_location: String
        try:
            new_location = original_response.headers[HeaderKey.LOCATION]
        except e:
            raise Error("Client._handle_redirect: `Location` header was not received in the response.")

        if new_location and new_location.startswith("http"):
            try:
                new_uri = URI.parse(new_location)
            except e:
                raise Error("Client._handle_redirect: Failed to parse the new URI: " + String(e))
            original_request.headers[HeaderKey.HOST] = new_uri.host
        else:
            new_uri = original_request.uri.copy()
            new_uri.path = new_location
        original_request.uri = new_uri^
        return self.do(original_request^)
