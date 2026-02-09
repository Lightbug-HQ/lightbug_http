from testing import TestSuite


def main():
    TestSuite.discover_tests[__functions_in_module()]().run()
