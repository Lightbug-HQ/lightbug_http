from collections import Dict

from lightbug_http._logger import logger
from lightbug_http.client import Client
from testing import *

from lightbug_http import *


fn u(s: String) raises -> URI:
    return URI.parse("http://127.0.0.1:8000/" + s)


struct IntegrationTest:
    var client: Client
    var results: Dict[String, String]

    fn __init__(out self):
        self.client = Client(allow_redirects=True)
        self.results = Dict[String, String]()

    fn mark_successful(mut self, name: String):
        self.results[name] = "✅"

    fn mark_failed(mut self, name: String):
        self.results[name] = "❌"

    fn test_redirect(mut self):
        comptime name = "test_redirect"
        print("\n~~~ Testing redirect ~~~")
        var h = Headers(Header(HeaderKey.CONNECTION, "keep-alive"))
        try:
            var res = self.client.do(HTTPRequest(u("redirect"), headers=h))
            assert_equal(res.status_code, StatusCode.OK)
            assert_equal(to_string(res.body_raw.copy()), "yay you made it")
            var conn = res.headers.get(HeaderKey.CONNECTION)
            if conn:
                assert_equal(conn.value(), "keep-alive")
            self.mark_successful(name)
        except e:
            logger.error("IntegrationTest.test_redirect has run into an error.")
            logger.error(e)
            self.mark_failed(name)
            return

    fn test_close_connection(mut self):
        comptime name = "test_close_connection"
        print("\n~~~ Testing close connection ~~~")
        var h = Headers(Header(HeaderKey.CONNECTION, "close"))
        try:
            var res = self.client.do(HTTPRequest(u("close-connection"), headers=h))
            assert_equal(res.status_code, StatusCode.OK)
            assert_equal(to_string(res.body_raw.copy()), "connection closed")
            assert_equal(res.headers[HeaderKey.CONNECTION], "close")
            self.mark_successful(name)
        except e:
            logger.error("IntegrationTest.test_close_connection has run into an error.")
            logger.error(e)
            self.mark_failed(name)
            return

    fn test_server_error(mut self):
        comptime name = "test_server_error"
        print("\n~~~ Testing internal server error ~~~")
        try:
            var res = self.client.do(HTTPRequest(u("error")))
            assert_equal(res.status_code, StatusCode.INTERNAL_ERROR)
            assert_equal(res.status_text, "Internal Server Error")
            self.mark_successful(name)
        except e:
            logger.error("IntegrationTest.test_server_error has run into an error.")
            logger.error(e)
            self.mark_failed(name)
            return

    fn run_tests(mut self) -> Dict[String, String]:
        logger.info("Running Client Integration Tests...")
        self.test_redirect()
        self.test_close_connection()
        self.test_server_error()

        return self.results.copy()


fn main():
    var test = IntegrationTest()
    var results = test.run_tests()
    for test in results.items():
        print(test.key + ":", test.value)
