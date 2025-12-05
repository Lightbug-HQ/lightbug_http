from lightbug_http.io.bytes import Bytes
from lightbug_http.strings import empty_string, to_string
from lightbug_http.uri import URI
from testing import TestSuite, assert_equal, assert_false, assert_raises, assert_true


def test_uri_no_parse_defaults():
    var uri = URI.parse("http://example.com")
    assert_equal(uri.full_uri, "http://example.com")
    assert_equal(uri.scheme, "http")
    assert_equal(uri.path, "/")


def test_uri_parse_http_with_port():
    var uri = URI.parse("http://example.com:8080/index.html")
    assert_equal(uri.scheme, "http")
    assert_equal(uri.host, "example.com")
    assert_equal(uri.port.value(), 8080)
    assert_equal(uri.path, "/index.html")
    assert_equal(uri._original_path, "/index.html")
    assert_equal(uri.request_uri, "/index.html")
    assert_equal(uri.is_https(), False)
    assert_equal(uri.is_http(), True)
    assert_equal(uri.query_string, empty_string)


def test_uri_parse_https_with_port():
    var uri = URI.parse("https://example.com:8080/index.html")
    assert_equal(uri.scheme, "https")
    assert_equal(uri.host, "example.com")
    assert_equal(uri.port.value(), 8080)
    assert_equal(uri.path, "/index.html")
    assert_equal(uri._original_path, "/index.html")
    assert_equal(uri.request_uri, "/index.html")
    assert_equal(uri.is_https(), True)
    assert_equal(uri.is_http(), False)
    assert_equal(uri.query_string, empty_string)


def test_uri_parse_http_with_path():
    var uri = URI.parse("http://example.com/index.html")
    assert_equal(uri.scheme, "http")
    assert_equal(uri.host, "example.com")
    assert_equal(uri.path, "/index.html")
    assert_equal(uri._original_path, "/index.html")
    assert_equal(uri.request_uri, "/index.html")
    assert_equal(uri.is_https(), False)
    assert_equal(uri.is_http(), True)
    assert_equal(uri.query_string, empty_string)


def test_uri_parse_https_with_path():
    var uri = URI.parse("https://example.com/index.html")
    assert_equal(uri.scheme, "https")
    assert_equal(uri.host, "example.com")
    assert_equal(uri.path, "/index.html")
    assert_equal(uri._original_path, "/index.html")
    assert_equal(uri.request_uri, "/index.html")
    assert_equal(uri.is_https(), True)
    assert_equal(uri.is_http(), False)
    assert_equal(uri.query_string, empty_string)

# TODO: Index OOB Error
# def test_uri_parse_path_with_encoding():
#     var uri = URI.parse("https://example.com/test%20test/index.html")
#     assert_equal(uri.path, "/test test/index.html")

# TODO: Index OOB Error
# def test_uri_parse_path_with_encoding_ignore_slashes():
#     var uri = URI.parse("https://example.com/trying_to%2F_be_clever/42.html")
#     assert_equal(uri.path, "/trying_to_be_clever/42.html")


def test_uri_parse_http_basic():
    var uri = URI.parse("http://example.com")
    assert_equal(uri.scheme, "http")
    assert_equal(uri.host, "example.com")
    assert_equal(uri.path, "/")
    assert_equal(uri._original_path, "/")
    assert_equal(uri.request_uri, "/")
    assert_equal(uri.query_string, empty_string)


def test_uri_parse_http_basic_www():
    var uri = URI.parse("http://www.example.com")
    assert_equal(uri.scheme, "http")
    assert_equal(uri.host, "www.example.com")
    assert_equal(uri.path, "/")
    assert_equal(uri._original_path, "/")
    assert_equal(uri.request_uri, "/")
    assert_equal(uri.query_string, empty_string)


def test_uri_parse_http_with_query_string():
    var uri = URI.parse("http://www.example.com/job?title=engineer")
    assert_equal(uri.scheme, "http")
    assert_equal(uri.host, "www.example.com")
    assert_equal(uri.path, "/job")
    assert_equal(uri._original_path, "/job")
    assert_equal(uri.request_uri, "/job?title=engineer")
    assert_equal(uri.query_string, "title=engineer")
    assert_equal(uri.queries["title"], "engineer")


def test_uri_parse_multiple_query_parameters():
    var uri = URI.parse("http://example.com/search?q=python&page=1&limit=20")
    assert_equal(uri.scheme, "http")
    assert_equal(uri.host, "example.com")
    assert_equal(uri.path, "/search")
    assert_equal(uri.query_string, "q=python&page=1&limit=20")
    assert_equal(uri.queries["q"], "python")
    assert_equal(uri.queries["page"], "1")
    assert_equal(uri.queries["limit"], "20")
    assert_equal(uri.request_uri, "/search?q=python&page=1&limit=20")


# TODO: Index OOB Error
# def test_uri_parse_query_with_special_characters():
#     var uri = URI.parse("https://example.com/path?name=John+Doe&email=john%40example.com&escaped%40%20name=42")
#     assert_equal(uri.scheme, "https")
#     assert_equal(uri.host, "example.com")
#     assert_equal(uri.path, "/path")
#     assert_equal(uri.query_string, "name=John+Doe&email=john%40example.com&escaped%40%20name=42")
#     assert_equal(uri.queries["name"], "John Doe")
#     assert_equal(uri.queries["email"], "john@example.com")
#     assert_equal(uri.queries["escaped@ name"], "42")


def test_uri_parse_empty_query_values():
    var uri = URI.parse("http://example.com/api?key=&token=&empty")
    assert_equal(uri.query_string, "key=&token=&empty")
    assert_equal(uri.queries["key"], "")
    assert_equal(uri.queries["token"], "")
    assert_equal(uri.queries["empty"], "")


def test_uri_parse_complex_query():
    var uri = URI.parse("https://example.com/search?q=test&filter[category]=books&filter[price]=10-20&sort=desc&page=1")
    assert_equal(uri.scheme, "https")
    assert_equal(uri.host, "example.com")
    assert_equal(uri.path, "/search")
    assert_equal(uri.query_string, "q=test&filter[category]=books&filter[price]=10-20&sort=desc&page=1")
    assert_equal(uri.queries["q"], "test")
    assert_equal(uri.queries["filter[category]"], "books")
    assert_equal(uri.queries["filter[price]"], "10-20")
    assert_equal(uri.queries["sort"], "desc")
    assert_equal(uri.queries["page"], "1")


# TODO: Index OOB Error
# def test_uri_parse_query_with_unicode():
#     var uri = URI.parse("http://example.com/search?q=%E2%82%AC&lang=%F0%9F%87%A9%F0%9F%87%AA")
#     assert_equal(uri.query_string, "q=%E2%82%AC&lang=%F0%9F%87%A9%F0%9F%87%AA")
#     assert_equal(uri.queries["q"], "€")
#     assert_equal(uri.queries["lang"], "🇩🇪")


# def test_uri_parse_query_with_fragments():
#     var uri = URI.parse("http://example.com/page?id=123#section1")
#     assert_equal(uri.query_string, "id=123")
#     assert_equal(uri.queries["id"], "123")
#     assert_equal(...) - how do we treat fragments?


def test_uri_parse_no_scheme():
    var uri = URI.parse("www.example.com")
    assert_equal(uri.scheme, "http")
    assert_equal(uri.host, "www.example.com")


def test_uri_ip_address_no_scheme():
    var uri = URI.parse("168.22.0.1/path/to/favicon.ico")
    assert_equal(uri.scheme, "http")
    assert_equal(uri.host, "168.22.0.1")
    assert_equal(uri.path, "/path/to/favicon.ico")


def test_uri_ip_address():
    var uri = URI.parse("http://168.22.0.1:8080/path/to/favicon.ico")
    assert_equal(uri.scheme, "http")
    assert_equal(uri.host, "168.22.0.1")
    assert_equal(uri.path, "/path/to/favicon.ico")
    assert_equal(uri.port.value(), 8080)


# def test_uri_parse_http_with_hash():
#     ...

def main():
    TestSuite.discover_tests[__functions_in_module()]().run()
