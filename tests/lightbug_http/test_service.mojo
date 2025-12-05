import testing
from lightbug_http.service import Counter, ExampleRouter, Printer, TechEmpowerRouter, Welcome


def test_printer():
    pass


def test_welcome():
    pass


def test_example_router():
    pass


def test_tech_empower_router():
    pass


def test_counter():
    pass

def main():
    testing.TestSuite.discover_tests[__functions_in_module()]().run()
