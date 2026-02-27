climport testing
from testing import assert_equal, assert_true

from emberjson import parse
from lightbug_http.header import HeaderKey
from lightbug_http.http.json import JsonOK, JsonError


def test_json_ok_status_and_content_type():
    var res = JsonOK('{"message": "hello"}')
    assert_equal(res.status_code, 200)
    assert_equal(res.headers[HeaderKey.CONTENT_TYPE], "application/json")


def test_json_ok_preserves_body():
    var body = '{"key": "value", "num": 42}'
    var res = JsonOK(body)
    assert_equal(String(res.get_body()), body)


def test_json_ok_empty_object():
    var res = JsonOK("{}")
    assert_equal(String(res.get_body()), "{}")
    assert_equal(res.headers[HeaderKey.CONTENT_TYPE], "application/json")


def test_json_error_status_and_content_type():
    var res = JsonError("invalid input")
    assert_equal(res.status_code, 400)
    assert_equal(res.headers[HeaderKey.CONTENT_TYPE], "application/json")


def test_json_error_contains_message():
    var res = JsonError("bad request")
    var body = String(res.get_body())
    assert_true("bad request" in body, "error body should contain the message")
    assert_true("error" in body, "error body should contain 'error' key")


def test_json_error_is_valid_json():
    var res = JsonError("something went wrong")
    var body = String(res.get_body())
    # Verify the error response body is parseable JSON
    var json = parse(body)
    assert_equal(String(json["error"]), '"something went wrong"')


def main():
    testing.TestSuite.discover_tests[__functions_in_module()]().run()
