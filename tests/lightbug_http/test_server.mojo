import testing
from lightbug_http.server import Server


def test_server_defaults_to_keep_alive_off():
    var server = Server()
    testing.assert_false(
        server.tcp_keep_alive,
        "tcp_keep_alive must default to False for single-threaded server",
    )


def main():
    testing.TestSuite.discover_tests[__functions_in_module()]().run()
