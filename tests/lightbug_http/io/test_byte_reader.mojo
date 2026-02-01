import testing
from lightbug_http.io.bytes import ByteReader, Bytes, EndOfReaderError


comptime example = "Hello, World!"


def test_peek():
    var r = ByteReader("H".as_bytes())
    var b: Byte
    try:
        b = r.peek()
    except EndOfReaderError:
        raise Error("Did not expect EndOfReaderError here.")
    testing.assert_equal(b, 72)

    # Peeking does not move the reader.
    try:
        b = r.peek()
    except EndOfReaderError:
        raise Error("Did not expect EndOfReaderError here.")
    testing.assert_equal(b, 72)

    # Trying to peek past the end of the reader should raise an Error
    r.read_pos = 1
    with testing.assert_raises(contains="No more bytes to read."):
        _ = r.peek()


def test_read_until():
    var r = ByteReader(example.as_bytes())
    var result: List[Byte] = [72, 101, 108, 108, 111]
    testing.assert_equal(r.read_pos, 0)
    testing.assert_equal(
        String(unsafe_from_utf8=r.read_until(ord(",")).as_bytes()), String(unsafe_from_utf8=result)
    )
    testing.assert_equal(r.read_pos, 5)


def test_read_bytes():
    var r = ByteReader(example.as_bytes())
    var result: List[Byte] = [
        72,
        101,
        108,
        108,
        111,
        44,
        32,
        87,
        111,
        114,
        108,
        100,
        33,
    ]
    testing.assert_equal(
        String(unsafe_from_utf8=r.read_bytes().as_bytes()), String(unsafe_from_utf8=result)
    )

    r = ByteReader(example.as_bytes())
    var result2: List[Byte] = [72, 101, 108, 108, 111, 44, 32]
    var bytes: Span[Byte, StaticConstantOrigin]
    try:
        bytes = r.read_bytes(7).as_bytes()
    except EndOfReaderError:
        raise Error("Did not expect EndOfReaderError here.")
    testing.assert_equal(String(unsafe_from_utf8=bytes), String(unsafe_from_utf8=result2))

    var result3: List[Byte] = [87, 111, 114, 108, 100, 33]
    testing.assert_equal(
        String(unsafe_from_utf8=r.read_bytes().as_bytes()), String(unsafe_from_utf8=result3)
    )


def test_read_word():
    var r = ByteReader(example.as_bytes())
    var result: List[Byte] = [72, 101, 108, 108, 111, 44]
    testing.assert_equal(r.read_pos, 0)
    testing.assert_equal(
        String(unsafe_from_utf8=r.read_word().as_bytes()), String(unsafe_from_utf8=result)
    )
    testing.assert_equal(r.read_pos, 6)


def test_read_line():
    # No newline, go to end of line
    var r = ByteReader(example.as_bytes())
    var result: List[Byte] = [
        72,
        101,
        108,
        108,
        111,
        44,
        32,
        87,
        111,
        114,
        108,
        100,
        33,
    ]
    testing.assert_equal(r.read_pos, 0)
    testing.assert_equal(
        String(unsafe_from_utf8=r.read_line().as_bytes()), String(unsafe_from_utf8=result)
    )
    testing.assert_equal(r.read_pos, 13)

    # Newline, go to end of line. Should cover carriage return and newline
    var r2 = ByteReader("Hello\r\nWorld\n!".as_bytes())
    var result2: List[Byte] = [72, 101, 108, 108, 111]
    var result3: List[Byte] = [87, 111, 114, 108, 100]
    testing.assert_equal(r2.read_pos, 0)
    testing.assert_equal(
        String(unsafe_from_utf8=r2.read_line().as_bytes()), String(unsafe_from_utf8=result2)
    )
    testing.assert_equal(r2.read_pos, 7)
    testing.assert_equal(
        String(unsafe_from_utf8=r2.read_line().as_bytes()), String(unsafe_from_utf8=result3)
    )
    testing.assert_equal(r2.read_pos, 13)


def test_skip_whitespace():
    var r = ByteReader(" Hola".as_bytes())
    var result: List[Byte] = [72, 111, 108, 97]
    r.skip_whitespace()
    testing.assert_equal(r.read_pos, 1)
    testing.assert_equal(
        String(unsafe_from_utf8=r.read_word().as_bytes()), String(unsafe_from_utf8=result)
    )


def test_skip_carriage_return():
    var r = ByteReader("\r\nHola".as_bytes())
    var result: List[Byte] = [72, 111, 108, 97]
    r.skip_carriage_return()
    testing.assert_equal(r.read_pos, 2)

    var bytes: Span[Byte, StaticConstantOrigin]
    try:
        bytes = r.read_bytes(4).as_bytes()
    except EndOfReaderError:
        raise Error("Did not expect EndOfReaderError here.")
    testing.assert_equal(String(unsafe_from_utf8=bytes), String(unsafe_from_utf8=result))


def test_consume():
    var r = ByteReader(example.as_bytes())
    var result: List[Byte] = [
        72,
        101,
        108,
        108,
        111,
        44,
        32,
        87,
        111,
        114,
        108,
        100,
        33,
    ]
    testing.assert_equal(String(unsafe_from_utf8=r^.consume()), String(unsafe_from_utf8=result))


def main():
    testing.TestSuite.discover_tests[__functions_in_module()]().run()
