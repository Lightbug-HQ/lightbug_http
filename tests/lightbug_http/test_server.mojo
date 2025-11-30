from testing import assert_equal, TestSuite
from lightbug_http.server import Server


# fn test_server() raises:
#     var server = Server()
#     server.set_address("0.0.0.0")
#     assert_equal(server.address(), "0.0.0.0")
#     server.set_max_request_body_size(1024)
#     assert_equal(server.max_request_body_size(), 1024)
#     assert_equal(server.get_concurrency(), 1000)

#     server = Server(max_concurrent_connections=10)
#     assert_equal(server.get_concurrency(), 10)


def main():
    TestSuite.discover_tests[__functions_in_module()]().run()
