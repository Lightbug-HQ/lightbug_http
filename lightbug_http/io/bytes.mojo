from memory.span import Span, _SpanIter, UnsafePointer
from lightbug_http.strings import BytesConstant
from lightbug_http.connection import default_buffer_size


alias Bytes = List[Byte]


@always_inline
fn byte(s: String) -> Byte:
    return ord(s)


@always_inline
fn bytes(s: String) -> Bytes:
    return Bytes(s.as_bytes())


@always_inline
fn is_newline(b: Byte) -> Bool:
    return b == BytesConstant.nChar or b == BytesConstant.rChar


@always_inline
fn is_space(b: Byte) -> Bool:
    return b == BytesConstant.whitespace


struct ByteWriter(Writer):
    var _inner: Bytes

    fn __init__(out self, capacity: Int = default_buffer_size):
        self._inner = Bytes(capacity=capacity)

    @always_inline
    fn write_bytes(mut self, bytes: Span[Byte]) -> None:
        """Writes the contents of `bytes` into the internal buffer.

        Args:
            bytes: The bytes to write.
        """
        self._inner.extend(bytes)

    fn write[*Ts: Writable](mut self, *args: *Ts) -> None:
        """Write data to the `Writer`.

        Parameters:
            Ts: The types of data to write.

        Args:
            args: The data to write.
        """

        @parameter
        for i in range(args.__len__()):
            args[i].write_to(self)

    @always_inline
    fn consuming_write(mut self, var b: Bytes):
        self._inner.extend(b^)

    @always_inline
    fn write_byte(mut self, b: Byte):
        self._inner.append(b)

    fn consume(var self) -> Bytes:
        var ret = self._inner^
        self._inner = Bytes()
        return ret^


alias EndOfReaderError = "No more bytes to read."
alias OutOfBoundsError = "Tried to read past the end of the ByteReader."


struct ByteView[origin: Origin](Sized, Stringable):
    """Convenience wrapper around a Span of Bytes."""

    var _inner: Span[Byte, origin]

    @implicit
    fn __init__(out self, b: Span[Byte, origin]):
        self._inner = b

    fn __len__(self) -> Int:
        return len(self._inner)

    fn __bool__(self) -> Bool:
        return self._inner.__bool__()

    fn __contains__(self, b: Byte) -> Bool:
        for i in range(len(self._inner)):
            if self._inner[i] == b:
                return True
        return False

    fn __contains__(self, b: Bytes) -> Bool:
        if len(b) > len(self._inner):
            return False

        for i in range(len(self._inner) - len(b) + 1):
            var found = True
            for j in range(len(b)):
                if self._inner[i + j] != b[j]:
                    found = False
                    break
            if found:
                return True
        return False

    fn __getitem__(self, index: Int) -> Byte:
        return self._inner[index]

    fn __getitem__(self, slc: Slice) -> Self:
        return Self(self._inner[slc])

    fn __str__(self) -> String:
        return String(StringSlice(unsafe_from_utf8=self._inner))

    fn __eq__(self, other: Self) -> Bool:
        # both empty
        if not self._inner and not other._inner:
            return True
        if len(self) != len(other):
            return False

        for i in range(len(self)):
            if self[i] != other[i]:
                return False
        return True

    fn __eq__(self, other: Span[Byte]) -> Bool:
        # both empty
        if not self._inner and not other:
            return True
        if len(self) != len(other):
            return False

        for i in range(len(self)):
            if self[i] != other[i]:
                return False
        return True

    fn __eq__(self, other: Bytes) -> Bool:
        # Check if lengths match
        if len(self) != len(other):
            return False

        # Compare each byte
        for i in range(len(self)):
            if self[i] != other[i]:
                return False
        return True

    fn __ne__(self, other: Self) -> Bool:
        return not self == other

    fn __ne__(self, other: Span[Byte]) -> Bool:
        return not self == other

    fn __iter__(self) -> _SpanIter[Byte, origin]:
        return self._inner.__iter__()

    fn find(self, target: Byte) -> Int:
        """Finds the index of a byte in a byte span.

        Args:
            target: The byte to find.

        Returns:
            The index of the byte in the span, or -1 if not found.
        """
        for i in range(len(self)):
            if self[i] == target:
                return i

        return -1

    fn rfind(self, target: Byte) -> Int:
        """Finds the index of the last occurrence of a byte in a byte span.

        Args:
            target: The byte to find.

        Returns:
            The index of the last occurrence of the byte in the span, or -1 if not found.
        """
        # Start from the end and work backwards
        var i = len(self) - 1
        while i >= 0:
            if self[i] == target:
                return i
            i -= 1

        return -1

    fn to_bytes(self) -> Bytes:
        return Bytes(self._inner)


struct ByteReader[origin: Origin](Sized):
    var _inner: Span[Byte, origin]
    var read_pos: Int

    fn __init__(out self, b: Span[Byte, origin]):
        self._inner = b
        self.read_pos = 0

    fn copy(self) -> Self:
        return ByteReader(self._inner[self.read_pos :])

    fn __contains__(self, b: Byte) -> Bool:
        for i in range(self.read_pos, len(self._inner)):
            if self._inner[i] == b:
                return True
        return False

    @always_inline
    fn available(self) -> Bool:
        return self.read_pos < len(self._inner)

    fn __len__(self) -> Int:
        return len(self._inner) - self.read_pos

    fn peek(self) raises -> Byte:
        if not self.available():
            raise EndOfReaderError
        return self._inner[self.read_pos]

    fn read_bytes(mut self, n: Int = -1) raises -> ByteView[origin]:
        var count = n
        var start = self.read_pos
        if n == -1:
            count = len(self)

        if start + count > len(self._inner):
            raise OutOfBoundsError

        self.read_pos += count
        return self._inner[start : start + count]

    fn read_until(mut self, char: Byte) -> ByteView[origin]:
        var start = self.read_pos
        for i in range(start, len(self._inner)):
            if self._inner[i] == char:
                break
            self.increment()

        return self._inner[start : self.read_pos]

    @always_inline
    fn read_word(mut self) -> ByteView[origin]:
        return self.read_until(BytesConstant.whitespace)

    fn read_line(mut self) -> ByteView[origin]:
        var start = self.read_pos
        for i in range(start, len(self._inner)):
            if is_newline(self._inner[i]):
                break
            self.increment()

        # If we are at the end of the buffer, there is no newline to check for.
        var ret = self._inner[start : self.read_pos]
        if not self.available():
            return ret

        if self._inner[self.read_pos] == BytesConstant.rChar:
            self.increment(2)
        else:
            self.increment()
        return ret

    @always_inline
    fn skip_whitespace(mut self):
        for i in range(self.read_pos, len(self._inner)):
            if is_space(self._inner[i]):
                self.increment()
            else:
                break

    @always_inline
    fn skip_carriage_return(mut self):
        for i in range(self.read_pos, len(self._inner)):
            if self._inner[i] == BytesConstant.rChar:
                self.increment(2)
            else:
                break

    @always_inline
    fn increment(mut self, v: Int = 1):
        self.read_pos += v

    @always_inline
    fn consume(var self, bytes_len: Int = -1) -> Bytes:
        return Bytes(self^._inner[self.read_pos : self.read_pos + len(self) + 1])
