from hashlib.hash import Hasher

from lightbug_http._logger import logger
from lightbug_http._owning_list import OwningList
from lightbug_http.connection import Connection, TCPConnection, create_connection
from lightbug_http.uri import Scheme


@fieldwise_init
struct PoolKey(Hashable, ImplicitlyCopyable, KeyElement, Stringable, Writable):
    var host: String
    var port: UInt16
    var scheme: Scheme

    fn __hash__[H: Hasher](self, mut hasher: H):
        # TODO: Very rudimentary hash. We probably need to actually have an actual hash function here.
        # Since Tuple doesn't have one.
        # return hash(hash(self.host) + hash(self.port) + hash(self.scheme))
        hasher.update(self.host + "-" + String(self.port) + "-" + String(self.scheme))

    fn __eq__(self, other: Self) -> Bool:
        return self.host == other.host and self.port == other.port and self.scheme == other.scheme

    fn __ne__(self, other: Self) -> Bool:
        return self.host != other.host or self.port != other.port or self.scheme != other.scheme

    fn __str__(self) -> String:
        var result = String()
        result.write(self.scheme.value, "://", self.host, ":", String(self.port))
        return result

    fn __repr__(self) -> String:
        return String.write(self)

    fn write_to[W: Writer, //](self, mut writer: W) -> None:
        writer.write(
            "PoolKey(",
            "scheme=",
            repr(self.scheme.value),
            ", host=",
            repr(self.host),
            ", port=",
            String(self.port),
            ")",
        )


struct PoolManager[ConnectionType: Connection]():
    var _connections: OwningList[ConnectionType]
    var _capacity: Int
    var mapping: Dict[PoolKey, Int]

    fn __init__(out self, capacity: Int = 10):
        self._connections = OwningList[ConnectionType](capacity=capacity)
        self._capacity = capacity
        self.mapping = Dict[PoolKey, Int]()

    fn __del__(deinit self):
        logger.debug(
            "PoolManager shutting down and closing remaining connections before destruction:", self._connections.size
        )
        self.clear()

    fn give(mut self, key: PoolKey, var value: ConnectionType) raises:
        if key in self.mapping:
            self._connections[self.mapping[key]] = value^
            return

        if self._connections.size == self._capacity:
            raise Error("PoolManager.give: Cache is full.")

        self._connections.append(value^)
        self.mapping[key] = self._connections.size - 1
        logger.debug("Checked in connection for peer:", String(key) + ", at index:", self._connections.size)

    fn take(mut self, key: PoolKey) raises -> ConnectionType:
        var index: Int
        try:
            index = self.mapping[key]
            _ = self.mapping.pop(key)
        except:
            raise Error("PoolManager.take: Key not found.")

        var connection = self._connections.pop(index)
        #  Shift everything over by one
        for ref value in self.mapping.values():
            if value > index:
                value -= 1

        logger.debug("Checked out connection for peer:", String(key) + ", from index:", self._connections.size + 1)
        return connection^

    fn clear(mut self):
        while self._connections:
            var connection = self._connections.pop(0)
            try:
                connection^.teardown()
            except e:
                # TODO: This is used in __del__, would be nice if we didn't have to absorb the error.
                logger.error("Failed to tear down connection. Error:", e)
        self.mapping.clear()

    fn __contains__(self, key: PoolKey) -> Bool:
        return key in self.mapping

    fn __setitem__(mut self, key: PoolKey, var value: ConnectionType) raises -> None:
        if key in self.mapping:
            self._connections[self.mapping[key]] = value^
        else:
            self.give(key, value^)

    fn __getitem__(self, key: PoolKey) raises -> ref [self._connections] ConnectionType:
        return self._connections[self.mapping[key]]
