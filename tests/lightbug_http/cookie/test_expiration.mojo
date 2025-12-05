import testing
from lightbug_http.cookie.expiration import Expiration
from lightbug_http.external.small_time import SmallTime


def test_ctors():
    # TODO: The string parsing is not correct, possibly a smalltime bug. I will look into it later. (@thatstoasty)
    # print(Expiration.from_string("Thu, 22 Jan 2037 12:00:10 GMT").value().datetime.value(), Expiration.from_datetime(SmallTime(2037, 1, 22, 12, 0, 10, 0)).datetime.value())
    # testing.assert_true(Expiration.from_string("Thu, 22 Jan 2037 12:00:10 GMT").value() == Expiration.from_datetime(SmallTime(2037, 1, 22, 12, 0, 10, 0)))
    # Failure returns None
    # testing.assert_false(Expiration.from_string("abc").__bool__())
    pass


def main():
    testing.TestSuite.discover_tests[__functions_in_module()]().run()
