import testing
from lightbug_http.cookie.duration import Duration


def test_from_string():
    testing.assert_equal(Duration.from_string("10").value().total_seconds, 10)
    testing.assert_false(Duration.from_string("10s").__bool__())


def test_ctor():
    testing.assert_equal(Duration(seconds=1, minutes=1, hours=1, days=1).total_seconds, 90061)

def main():
    testing.TestSuite.discover_tests[__functions_in_module()]().run()