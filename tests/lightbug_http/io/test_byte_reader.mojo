import testing
from lightbug_http.io.bytes import Bytes, ByteReader, EndOfReaderError
from lightbug_http.strings import to_string

alias example = "Hello, World!"


def test_peek():
    var r = ByteReader("H".as_bytes())
    testing.assert_equal(r.peek(), 72)

    # Peeking does not move the reader.
    testing.assert_equal(r.peek(), 72)

    # Trying to peek past the end of the reader should raise an Error
    r.read_pos = 1
    with testing.assert_raises(contains="No more bytes to read."):
        _ = r.peek()
def test_read_until():
    var r = ByteReader(example.as_bytes())
    testing.assert_equal(r.read_pos, 0)
    testing.assert_equal(to_string(r.read_until(ord(",")).to_bytes()), to_string(Bytes(72, 101, 108, 108, 111)))
    testing.assert_equal(r.read_pos, 5)


def test_read_bytes():
    var r = ByteReader(example.as_bytes())
    testing.assert_equal(to_string(r.read_bytes().to_bytes()), to_string(Bytes(72, 101, 108, 108, 111, 44, 32, 87, 111, 114, 108, 100, 33)))

    r = ByteReader(example.as_bytes())
    testing.assert_equal(to_string(r.read_bytes(7).to_bytes()), to_string(Bytes(72, 101, 108, 108, 111, 44, 32)))
    testing.assert_equal(to_string(r.read_bytes().to_bytes()), to_string(Bytes(87, 111, 114, 108, 100, 33)))


def test_read_word():
    var r = ByteReader(example.as_bytes())
    testing.assert_equal(r.read_pos, 0)
    testing.assert_equal(to_string(r.read_word().to_bytes()), to_string(Bytes(72, 101, 108, 108, 111, 44)))
    testing.assert_equal(r.read_pos, 6)


def test_read_line():
    # No newline, go to end of line
    var r = ByteReader(example.as_bytes())
    testing.assert_equal(r.read_pos, 0)
    testing.assert_equal(to_string(r.read_line().to_bytes()), to_string(Bytes(72, 101, 108, 108, 111, 44, 32, 87, 111, 114, 108, 100, 33)))
    testing.assert_equal(r.read_pos, 13)

    # Newline, go to end of line. Should cover carriage return and newline
    var r2 = ByteReader("Hello\r\nWorld\n!".as_bytes())
    testing.assert_equal(r2.read_pos, 0)
    testing.assert_equal(to_string(r2.read_line().to_bytes()), to_string(Bytes(72, 101, 108, 108, 111)))
    testing.assert_equal(r2.read_pos, 7)
    testing.assert_equal(to_string(r2.read_line().to_bytes()), to_string(Bytes(87, 111, 114, 108, 100)))
    testing.assert_equal(r2.read_pos, 13)


def test_skip_whitespace():
    var r = ByteReader(" Hola".as_bytes())
    r.skip_whitespace()
    testing.assert_equal(r.read_pos, 1)
    testing.assert_equal(to_string(r.read_word().to_bytes()), to_string(Bytes(72, 111, 108, 97)))


def test_skip_carriage_return():
    var r = ByteReader("\r\nHola".as_bytes())
    r.skip_carriage_return()
    testing.assert_equal(r.read_pos, 2)
    testing.assert_equal(to_string(r.read_bytes(4).to_bytes()), to_string(Bytes(72, 111, 108, 97)))


def test_consume():
    var r = ByteReader(example.as_bytes())
    testing.assert_equal(to_string(r^.consume()), to_string(Bytes(72, 101, 108, 108, 111, 44, 32, 87, 111, 114, 108, 100, 33)))

def main():
    testing.TestSuite.discover_tests[__functions_in_module()]().run()