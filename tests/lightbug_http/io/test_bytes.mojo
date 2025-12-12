import testing
from lightbug_http.io.bytes import Bytes, ByteView


fn test_string_literal_to_bytes() raises:
    var cases = Dict[StaticString, Bytes]()
    cases[""] = Bytes()
    cases["Hello world!"] = [72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100, 33]
    cases["\0"] = [0]
    cases["\0\0\0\0"] = [0, 0, 0, 0]
    cases["OK"] = [79, 75]
    cases["HTTP/1.1 200 OK"] = [72, 84, 84, 80, 47, 49, 46, 49, 32, 50, 48, 48, 32, 79, 75]

    for c in cases.items():
        testing.assert_equal(c.key, String(bytes=c.value))


fn test_string_to_bytes() raises:
    var cases = Dict[String, Bytes]()
    cases[String("")] = Bytes()
    cases[String("Hello world!")] = [72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100, 33]
    cases[String("\0")] = [0]
    cases[String("\0\0\0\0")] = [0, 0, 0, 0]
    cases[String("OK")] = [79, 75]
    cases[String("HTTP/1.1 200 OK")] = [72, 84, 84, 80, 47, 49, 46, 49, 32, 50, 48, 48, 32, 79, 75]

    for c in cases.items():
        testing.assert_equal(c.key, String(bytes=c.value))

def main():
    testing.TestSuite.discover_tests[__functions_in_module()]().run()
