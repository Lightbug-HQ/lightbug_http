import testing
from collections import Dict, List
from lightbug_http.io.bytes import Bytes, ByteView, bytes
from lightbug_http.strings import to_string


fn test_string_literal_to_bytes() raises:
    var cases = Dict[StaticString, Bytes]()
    cases[""] = Bytes()
    cases["Hello world!"] = Bytes(72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100, 33)
    cases["\0"] = Bytes(0)
    cases["\0\0\0\0"] = Bytes(0, 0, 0, 0)
    cases["OK"] = Bytes(79, 75)
    cases["HTTP/1.1 200 OK"] = Bytes(72, 84, 84, 80, 47, 49, 46, 49, 32, 50, 48, 48, 32, 79, 75)

    for c in cases.items():
        testing.assert_equal(to_string(Bytes(c.key.as_bytes())), to_string(c.copy().value.copy()))


fn test_string_to_bytes() raises:
    var cases = Dict[String, Bytes]()
    cases[String("")] = Bytes()
    cases[String("Hello world!")] = Bytes(72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100, 33)
    cases[String("\0")] = Bytes(0)
    cases[String("\0\0\0\0")] = Bytes(0, 0, 0, 0)
    cases[String("OK")] = Bytes(79, 75)
    cases[String("HTTP/1.1 200 OK")] = Bytes(72, 84, 84, 80, 47, 49, 46, 49, 32, 50, 48, 48, 32, 79, 75)

    for c in cases.items():
        testing.assert_equal(to_string(Bytes(c.key.as_bytes())), to_string(c.copy().value.copy()))

def main():
    testing.TestSuite.discover_tests[__functions_in_module()]().run()