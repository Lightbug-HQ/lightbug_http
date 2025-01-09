from collections import Dict
from memory import UnsafePointer
from lightbug_http.libc import (
    c_int,
    AF_INET,
    SOCK_STREAM,
    socket,
    connect,
    send,
    recv,
    close,
)
from lightbug_http.strings import to_string
from lightbug_http.net import default_buffer_size
from lightbug_http.http import HTTPRequest, HTTPResponse, encode
from lightbug_http.header import Headers, HeaderKey
from lightbug_http.net import create_connection, TCPConnection
from lightbug_http.io.bytes import Bytes
from lightbug_http.utils import ByteReader, logger
from lightbug_http.pool_manager import PoolManager

struct Client:
    var host: String
    var port: Int
    var name: String

    var _connections: PoolManager

    fn __init__(out self, host: String = "127.0.0.1", port: Int = 8888):
        self.host = host
        self.port = port
        self.name = "lightbug_http_client"
        self._connections = PoolManager(10)

    # fn __del__(owned self):
    #     logger.info("Client.__del__")
    #     self._connections.clear()

    fn do(mut self, owned req: HTTPRequest) raises -> HTTPResponse:
        """The `do` method is responsible for sending an HTTP request to a server and receiving the corresponding response.

        It performs the following steps:
        1. Creates a connection to the server specified in the request.
        2. Sends the request body using the connection.
        3. Receives the response from the server.
        4. Closes the connection.
        5. Returns the received response as an `HTTPResponse` object.

        Note: The code assumes that the `HTTPRequest` object passed as an argument has a valid URI with a host and port specified.

        Args:
            req: An `HTTPRequest` object representing the request to be sent.

        Returns:
            The received response.

        Raises:
            Error: If there is a failure in sending or receiving the message.
        """
        if req.uri.host == "":
            raise Error("Client.do: Request failed because the host field is empty.")
        var is_tls = False

        if req.uri.is_https():
            is_tls = True

        var host_str: String
        var port: Int
        if ":" in req.uri.host:
            var host_port: List[String]
            try:
                host_port = req.uri.host.split(":")
            except:
                raise Error("Client.do: Failed to split host and port.")
            host_str = host_port[0]
            port = atol(host_port[1])
        else:
            host_str = req.uri.host
            if is_tls:
                port = 443
            else:
                port = 80

        # var conn: TCPConnection
        var cached_connection = False
        # var conn = create_connection(host_str, port)

        if host_str not in self._connections:
            try:
                logger.info("Creating a new connection to host.")
                self._connections.give(host_str, create_connection(host_str, port))
            except e:
                logger.error(e)
                raise Error("Client.do: Failed to create a connection to host.")
        # try:
        #     self._connections.mapping[host_str]
        #     cached_connection = True
        # except:
        #     # If connection is not cached, create a new one.
        #     try:
        #         # conn = create_connection(host_str, port)
        #         self._connections.mapping[host_str] = create_connection(host_str, port)
        #     except e:
        #         logger.error(e)
        #         raise Error("Client.do: Failed to create a connection to host.")

        var conn = self._connections.take(host_str)

        var bytes_sent: Int
        try:
            bytes_sent = conn.write(encode(req))
        except e:
            # Maybe peer reset ungracefully, so try a fresh connection
            if str(e) == "SendError: Connection reset by peer.":
                logger.debug("Client.do: Connection reset by peer. Trying a fresh connection.")
                conn.teardown()
                if cached_connection:
                    return self.do(req^)
            logger.error("Client.do: Failed to send message.")
            raise e

        # TODO: What if the response is too large for the buffer? We should read until the end of the response.
        var new_buf = Bytes(capacity=default_buffer_size)

        try:
            logger.info("Reading response from peer...")
            _ = conn.read(new_buf)
        except e:
            if str(e) == "EOF":
                conn.teardown()
                if cached_connection:
                    return self.do(req^)
                raise Error("Client.do: No response received from the server.")
            else:
                logger.error(e)
                raise Error("Client.do: Failed to read response from peer.")

        var res: HTTPResponse
        try:
            res = HTTPResponse.from_bytes(new_buf, conn)
        except e:
            logger.error("Failed to parse a response...")
            try:
                conn.teardown()
            except:
                logger.error("Failed to teardown connection...")
            raise e
        
        if res.is_redirect():
            conn.teardown()
            return self._handle_redirect(req^, res^)
        elif res.connection_close():
            logger.info("client should close connection!")
            conn.teardown()
        else:
            # Persist the connection by giving it back to the pool manager.
            self._connections.give(host_str, conn^)
        return res


    fn _handle_redirect(
        mut self, owned original_req: HTTPRequest, owned original_response: HTTPResponse
    ) raises -> HTTPResponse:
        var new_uri: URI
        var new_location: String
        try:
            new_location = original_response.headers[HeaderKey.LOCATION]
        except e:
            raise Error("Client._handle_redirect: `Location` header was not received in the response.")
        
        if new_location and new_location.startswith("http"):
            try:
                new_uri = URI.parse_raises(new_location)
            except e:
                raise Error("Client._handle_redirect: Failed to parse the new URI - " + str(e))
            original_req.headers[HeaderKey.HOST] = new_uri.host
        else:
            new_uri = original_req.uri
            new_uri.path = new_location
        original_req.uri = new_uri
        return self.do(original_req^)

    # fn _close_conn(mut self, host: String) raises:
    #     if host in self._connections:
    #     #     # self._connections.get(host).close()
    #         _ = self._connections.delete(host)
