from lightbug_http._owning_list import OwningList
from sys.info import size_of

from memory import LegacyUnsafePointer, Span
from testing import assert_equal, assert_false, assert_raises, assert_true, TestSuite


def test_mojo_issue_698():
    var list = OwningList[Float64]()
    for i in range(5):
        list.append(i)

    assert_equal(0.0, list[0])
    assert_equal(1.0, list[1])
    assert_equal(2.0, list[2])
    assert_equal(3.0, list[3])
    assert_equal(4.0, list[4])


def test_list():
    var list = OwningList[Int]()

    for i in range(5):
        list.append(i)

    assert_equal(5, len(list))
    assert_equal(5 * size_of[Int](), list.bytecount())
    assert_equal(0, list[0])
    assert_equal(1, list[1])
    assert_equal(2, list[2])
    assert_equal(3, list[3])
    assert_equal(4, list[4])

    assert_equal(0, list[-5])
    assert_equal(3, list[-2])
    assert_equal(4, list[-1])

    list[2] = -2
    assert_equal(-2, list[2])

    list[-5] = 5
    assert_equal(5, list[-5])
    list[-2] = 3
    assert_equal(3, list[-2])
    list[-1] = 7
    assert_equal(7, list[-1])


def test_list_clear():
    var list = OwningList[Int](capacity=3)
    list.append(1)
    list.append(2)
    list.append(3)
    assert_equal(len(list), 3)
    assert_equal(list.capacity, 3)
    list.clear()

    assert_equal(len(list), 0)
    assert_equal(list.capacity, 3)


def test_list_pop():
    var list = OwningList[Int]()
    # Test pop with index
    for i in range(6):
        list.append(i)

    # try popping from index 3 for 3 times
    for i in range(3, 6):
        assert_equal(i, list.pop(3))

    # list should have 3 elements now
    assert_equal(3, len(list))
    assert_equal(0, list[0])
    assert_equal(1, list[1])
    assert_equal(2, list[2])

    # Test pop with negative index
    for i in range(0, 2):
        assert_equal(i, list.pop(-len(list)))

    # test default index as well
    assert_equal(2, list.pop())
    list.append(2)
    assert_equal(2, list.pop())

    # list should be empty now
    assert_equal(0, len(list))
    # capacity should be 1 according to shrink_to_fit behavior
    assert_equal(1, list.capacity)


def test_list_resize():
    var l = OwningList[Int]()
    l.append(1)
    l.resize(0)
    assert_equal(len(l), 0)


def test_list_insert():
    #
    # Test the list [1, 2, 3] created with insert
    #

    v1 = OwningList[Int]()
    v1.insert(len(v1), 1)
    v1.insert(len(v1), 3)
    v1.insert(1, 2)

    assert_equal(len(v1), 3)
    assert_equal(v1[0], 1)
    assert_equal(v1[1], 2)
    assert_equal(v1[2], 3)

    #
    # Test the list [1, 2, 3, 4, 5] created with negative and positive index
    #

    v2 = OwningList[Int]()
    v2.insert(-1729, 2)
    v2.insert(len(v2), 3)
    v2.insert(len(v2), 5)
    v2.insert(-1, 4)
    v2.insert(-len(v2), 1)

    assert_equal(len(v2), 5)
    assert_equal(v2[0], 1)
    assert_equal(v2[1], 2)
    assert_equal(v2[2], 3)
    assert_equal(v2[3], 4)
    assert_equal(v2[4], 5)

    #
    # Test the list [1, 2, 3, 4] created with negative index
    #

    v3 = OwningList[Int]()
    v3.insert(-11, 4)
    v3.insert(-13, 3)
    v3.insert(-17, 2)
    v3.insert(-19, 1)

    assert_equal(len(v3), 4)
    assert_equal(v3[0], 1)
    assert_equal(v3[1], 2)
    assert_equal(v3[2], 3)
    assert_equal(v3[3], 4)

    #
    # Test the list [1, 2, 3, 4, 5, 6, 7, 8] created with insert
    #

    v4 = OwningList[Int]()
    for i in range(4):
        v4.insert(0, 4 - i)
        v4.insert(len(v4), 4 + i + 1)

    for i in range(len(v4)):
        assert_equal(v4[i], i + 1)


def test_list_index():
    var test_list_a = OwningList[Int]()
    test_list_a.append(10)
    test_list_a.append(20)
    test_list_a.append(30)
    test_list_a.append(40)
    test_list_a.append(50)

    # Basic Functionality Tests
    assert_equal(test_list_a.index(10), 0)
    assert_equal(test_list_a.index(30), 2)
    assert_equal(test_list_a.index(50), 4)
    with assert_raises(contains="ValueError: Given element is not in list"):
        _ = test_list_a.index(60)

    # Tests With Start Parameter
    assert_equal(test_list_a.index(30, start=1), 2)
    assert_equal(test_list_a.index(30, start=-4), 2)
    assert_equal(test_list_a.index(30, start=-1000), 2)
    with assert_raises(contains="ValueError: Given element is not in list"):
        _ = test_list_a.index(30, start=3)
    with assert_raises(contains="ValueError: Given element is not in list"):
        _ = test_list_a.index(30, start=5)

    # Tests With Start and End Parameters
    assert_equal(test_list_a.index(30, start=1, stop=3), 2)
    assert_equal(test_list_a.index(30, start=-4, stop=-2), 2)
    assert_equal(test_list_a.index(30, start=-1000, stop=1000), 2)
    with assert_raises(contains="ValueError: Given element is not in list"):
        _ = test_list_a.index(30, start=1, stop=2)
    with assert_raises(contains="ValueError: Given element is not in list"):
        _ = test_list_a.index(30, start=3, stop=1)

    # Tests With End Parameter Only
    assert_equal(test_list_a.index(30, stop=3), 2)
    assert_equal(test_list_a.index(30, stop=-2), 2)
    assert_equal(test_list_a.index(30, stop=1000), 2)
    with assert_raises(contains="ValueError: Given element is not in list"):
        _ = test_list_a.index(30, stop=1)
    with assert_raises(contains="ValueError: Given element is not in list"):
        _ = test_list_a.index(30, stop=2)
    with assert_raises(contains="ValueError: Given element is not in list"):
        _ = test_list_a.index(60, stop=50)

    # Edge Cases and Special Conditions
    assert_equal(test_list_a.index(10, start=-5, stop=-1), 0)
    assert_equal(test_list_a.index(10, start=0, stop=50), 0)
    with assert_raises(contains="ValueError: Given element is not in list"):
        _ = test_list_a.index(50, start=-5, stop=-1)
    with assert_raises(contains="ValueError: Given element is not in list"):
        _ = test_list_a.index(50, start=0, stop=-1)
    with assert_raises(contains="ValueError: Given element is not in list"):
        _ = test_list_a.index(10, start=-4, stop=-1)
    with assert_raises(contains="ValueError: Given element is not in list"):
        _ = test_list_a.index(10, start=5, stop=50)
    with assert_raises(contains="ValueError: Given element is not in list"):
        _ = OwningList[Int]().index(10)

    # Test empty slice
    with assert_raises(contains="ValueError: Given element is not in list"):
        _ = test_list_a.index(10, start=1, stop=1)
    # Test empty slice with 0 start and end
    with assert_raises(contains="ValueError: Given element is not in list"):
        _ = test_list_a.index(10, start=0, stop=0)

    var test_list_b = OwningList[Int]()
    test_list_b.append(10)
    test_list_b.append(20)
    test_list_b.append(30)
    test_list_b.append(20)
    test_list_b.append(10)

    # Test finding the first occurrence of an item
    assert_equal(test_list_b.index(10), 0)
    assert_equal(test_list_b.index(20), 1)

    # Test skipping the first occurrence with a start parameter
    assert_equal(test_list_b.index(20, start=2), 3)

    # Test constraining search with start and end, excluding last occurrence
    with assert_raises(contains="ValueError: Given element is not in list"):
        _ = test_list_b.index(10, start=1, stop=4)

    # Test search within a range that includes multiple occurrences
    assert_equal(test_list_b.index(20, start=1, stop=4), 1)

    # Verify error when constrained range excludes occurrences
    with assert_raises(contains="ValueError: Given element is not in list"):
        _ = test_list_b.index(20, start=4, stop=5)


def test_list_extend():
    #
    # Test extending the list [1, 2, 3] with itself
    #

    vec = OwningList[Int]()
    vec.append(1)
    vec.append(2)
    vec.append(3)

    assert_equal(len(vec), 3)
    assert_equal(vec[0], 1)
    assert_equal(vec[1], 2)
    assert_equal(vec[2], 3)

    var copy = OwningList[Int]()
    copy.append(1)
    copy.append(2)
    copy.append(3)
    vec.extend(copy^)

    # vec == [1, 2, 3, 1, 2, 3]
    assert_equal(len(vec), 6)
    assert_equal(vec[0], 1)
    assert_equal(vec[1], 2)
    assert_equal(vec[2], 3)
    assert_equal(vec[3], 1)
    assert_equal(vec[4], 2)
    assert_equal(vec[5], 3)


def test_list_extend_non_trivial():
    # Tests three things:
    #   - extend() for non-plain-old-data types
    #   - extend() with mixed-length self and other lists
    #   - extend() using optimal number of __moveinit__() calls

    # Preallocate with enough capacity to avoid reallocation making the
    # move count checks below flaky.
    var v1 = OwningList[String](capacity=5)
    v1.append(String("Hello"))
    v1.append(String("World"))

    var v2 = OwningList[String](capacity=3)
    v2.append(String("Foo"))
    v2.append(String("Bar"))
    v2.append(String("Baz"))

    v1.extend(v2^)

    assert_equal(len(v1), 5)
    assert_equal(v1[0], "Hello")
    assert_equal(v1[1], "World")
    assert_equal(v1[2], "Foo")
    assert_equal(v1[3], "Bar")
    assert_equal(v1[4], "Baz")


def test_2d_dynamic_list():
    var list = OwningList[OwningList[Int]]()

    for i in range(2):
        var v = OwningList[Int]()
        for j in range(3):
            v.append(i + j)
        list.append(v^)

    assert_equal(0, list[0][0])
    assert_equal(1, list[0][1])
    assert_equal(2, list[0][2])
    assert_equal(1, list[1][0])
    assert_equal(2, list[1][1])
    assert_equal(3, list[1][2])

    assert_equal(2, len(list))
    assert_equal(2, list.capacity)

    assert_equal(3, len(list[0]))

    list[0].clear()
    assert_equal(0, len(list[0]))
    assert_equal(4, list[0].capacity)

    list.clear()
    assert_equal(0, len(list))
    assert_equal(2, list.capacity)


def test_list_iter():
    var vs = OwningList[Int]()
    vs.append(1)
    vs.append(2)
    vs.append(3)

    # Borrow immutably
    fn sum(vs: OwningList[Int]) -> Int:
        var sum = 0
        for v in vs:
            sum += v[]
        return sum

    assert_equal(6, sum(vs))


def test_list_iter_mutable():
    var vs = OwningList[Int]()
    vs.append(1)
    vs.append(2)
    vs.append(3)

    for v in vs:
        v[] += 1

    var sum = 0
    for v in vs:
        sum += v[]

    assert_equal(9, sum)


def test_list_realloc_trivial_types():
    a = OwningList[Int]()
    for i in range(100):
        a.append(i)

    assert_equal(len(a), 100)
    for i in range(100):
        assert_equal(a[i], i)

    b = OwningList[Int8]()
    for i in range(100):
        b.append(Int8(i))

    assert_equal(len(b), 100)
    for i in range(100):
        assert_equal(b[i], Int8(i))


def test_list_boolable():
    var l = OwningList[Int]()
    l.append(1)
    assert_true(l)
    assert_false(OwningList[Int]())


def test_converting_list_to_string():
    # This is also testing the method `to_format` because
    # essentially, `OwningList.__str__()` just creates a String and applies `to_format` to it.
    # If we were to write unit tests for `to_format`, we would essentially copy-paste the code
    # of `OwningList.__str__()`
    var my_list = OwningList[Int]()
    my_list.append(1)
    my_list.append(2)
    my_list.append(3)
    assert_equal(my_list.__str__(), "[1, 2, 3]")

    var my_list4 = OwningList[String]()
    my_list4.append("a")
    my_list4.append("b")
    my_list4.append("c")
    my_list4.append("foo")
    assert_equal(my_list4.__str__(), "['a', 'b', 'c', 'foo']")


def test_list_contains():
    var x = OwningList[Int]()
    x.append(1)
    x.append(2)
    x.append(3)
    assert_false(0 in x)
    assert_true(1 in x)
    assert_false(4 in x)


def test_indexing():
    var l = OwningList[Int]()
    l.append(1)
    l.append(2)
    l.append(3)
    assert_equal(l[Int(1)], 2)
    # assert_equal(l[False], 1)
    # assert_equal(l[True], 2)
    assert_equal(l[2], 3)


# ===-------------------------------------------------------------------===#
# OwningList dtor tests
# ===-------------------------------------------------------------------===#
# var __g_dtor_count: Int = 0


# struct DtorCounter(Copyable, Movable):
#     # NOTE: payload is required because OwningList does not support zero sized structs.
#     var payload: Int

#     fn __init__(out self):
#         self.payload = 0

#     fn __init__(out self, *, other: Self):
#         self.payload = other.payload

#     fn __copyinit__(out self, existing: Self, /):
#         self.payload = existing.payload

#     fn __moveinit__(out self, owned existing: Self, /):
#         self.payload = existing.payload
#         existing.payload = 0

#     fn __del__(owned self):
#         __g_dtor_count += 1


# def inner_test_list_dtor():
#     # explicitly reset global counter
#     __g_dtor_count = 0

#     var l = OwningList[DtorCounter]()
#     assert_equal(__g_dtor_count, 0)

#     l.append(DtorCounter())
#     assert_equal(__g_dtor_count, 0)

#     l^.__del__()
#     assert_equal(__g_dtor_count, 1)


# def test_list_dtor():
#     # call another function to force the destruction of the list
#     inner_test_list_dtor()

#     # verify we still only ran the destructor once
#     assert_equal(__g_dtor_count, 1)


def test_list_repr():
    var l = OwningList[Int]()
    l.append(1)
    l.append(2)
    l.append(3)
    assert_equal(l.__repr__(), "[1, 2, 3]")
    var empty = OwningList[Int]()
    assert_equal(empty.__repr__(), "[]")

def main():
    TestSuite.discover_tests[__functions_in_module()]().run()