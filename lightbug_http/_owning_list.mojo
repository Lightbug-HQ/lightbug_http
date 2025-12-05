from collections import Optional
from os import abort
from sys import size_of
from sys.intrinsics import _type_is_eq

from memory import LegacyUnsafePointer, Pointer, Span, memcpy


# ===-----------------------------------------------------------------------===#
# List
# ===-----------------------------------------------------------------------===#


@fieldwise_init
struct _OwningListIter[
    list_mutability: Bool, //,
    T: Movable,
    list_origin: Origin[list_mutability],
    forward: Bool = True,
](Copyable, Movable):
    """Iterator for List.

    Parameters:
        list_mutability: Whether the reference to the list is mutable.
        T: The type of the elements in the list.
        list_origin: The origin of the List
        forward: The iteration direction. `False` is backwards.
    """

    comptime list_type = OwningList[T]

    var index: Int
    var src: Pointer[Self.list_type, list_origin]

    fn __iter__(self) -> Self:
        return self.copy()

    fn __next__(
        mut self,
    ) -> Pointer[T, list_origin]:
        @parameter
        if forward:
            self.index += 1
            return Pointer(to=self.src[][self.index - 1])
        else:
            self.index -= 1
            return Pointer(to=self.src[][self.index])

    @always_inline
    fn __has_next__(self) -> Bool:
        return self.__len__() > 0

    fn __len__(self) -> Int:
        @parameter
        if forward:
            return len(self.src[]) - self.index
        else:
            return self.index


struct OwningList[T: Movable](Boolable, Movable, Sized):
    """The `List` type is a dynamically-allocated list.

    It supports pushing and popping from the back resizing the underlying
    storage as needed.  When it is deallocated, it frees its memory.

    Parameters:
        T: The type of the elements.
    """

    # Fields
    var data: LegacyUnsafePointer[T]
    """The underlying storage for the list."""
    var size: Int
    """The number of elements in the list."""
    var capacity: Int
    """The amount of elements that can fit in the list without resizing it."""

    # ===-------------------------------------------------------------------===#
    # Life cycle methods
    # ===-------------------------------------------------------------------===#

    fn __init__(out self):
        """Constructs an empty list."""
        self.data = LegacyUnsafePointer[T]()
        self.size = 0
        self.capacity = 0

    fn __init__(out self, *, capacity: Int):
        """Constructs a list with the given capacity.

        Args:
            capacity: The requested capacity of the list.
        """
        self.data = LegacyUnsafePointer[T].alloc(capacity)
        self.size = 0
        self.capacity = capacity

    fn __moveinit__(out self, deinit existing: Self):
        """Move data of an existing list into a new one.

        Args:
            existing: The existing list.
        """
        self.data = existing.data
        self.size = existing.size
        self.capacity = existing.capacity

    fn __del__(deinit self):
        """Destroy all elements in the list and free its memory."""
        for i in range(self.size):
            (self.data + i).destroy_pointee()
        self.data.free()

    # ===-------------------------------------------------------------------===#
    # Operator dunders
    # ===-------------------------------------------------------------------===#

    fn __contains__[U: EqualityComparable & Movable, //](self: OwningList[U, *_], value: U) -> Bool:
        """Verify if a given value is present in the list.

        Parameters:
            U: The type of the elements in the list. Must implement the
              traits `EqualityComparable`, `Copyable`, and `Movable`.

        Args:
            value: The value to find.

        Returns:
            True if the value is contained in the list, False otherwise.
        """
        for i in self:
            if i[] == value:
                return True
        return False

    fn __iter__(ref self) -> _OwningListIter[T, origin_of(self)]:
        """Iterate over elements of the list, returning immutable references.

        Returns:
            An iterator of immutable references to the list elements.
        """
        return _OwningListIter(0, Pointer(to=self))

    # ===-------------------------------------------------------------------===#
    # Trait implementations
    # ===-------------------------------------------------------------------===#

    fn __len__(self) -> Int:
        """Gets the number of elements in the list.

        Returns:
            The number of elements in the list.
        """
        return self.size

    fn __bool__(self) -> Bool:
        """Checks whether the list has any elements or not.

        Returns:
            `False` if the list is empty, `True` if there is at least one element.
        """
        return len(self) > 0

    @no_inline
    fn __str__[U: Representable & Movable, //](self: OwningList[U, *_]) -> String:
        """Returns a string representation of a `List`.

        When the compiler supports conditional methods, then a simple `String(my_list)` will
        be enough.

        The elements' type must implement the `__repr__()` method for this to work.

        Parameters:
            U: The type of the elements in the list. Must implement the
              traits `Representable` and `Movable`.

        Returns:
            A string representation of the list.
        """
        var output = String()
        self.write_to(output)
        return output^

    @no_inline
    fn write_to[W: Writer, U: Representable & Movable, //](self: OwningList[U, *_], mut writer: W):
        """Write `my_list.__str__()` to a `Writer`.

        Parameters:
            W: A type conforming to the Writable trait.
            U: The type of the List elements. Must have the trait `Representable & Movable`.

        Args:
            writer: The object to write to.
        """
        writer.write("[")
        for i in range(len(self)):
            writer.write(repr(self[i]))
            if i < len(self) - 1:
                writer.write(", ")
        writer.write("]")

    @no_inline
    fn __repr__[U: Representable & Movable, //](self: OwningList[U, *_]) -> String:
        """Returns a string representation of a `List`.

        Note that since we can't condition methods on a trait yet,
        the way to call this method is a bit special. Here is an example below:

        ```mojo
        var my_list = List[Int](1, 2, 3)
        print(my_list.__repr__())
        ```

        When the compiler supports conditional methods, then a simple `repr(my_list)` will
        be enough.

        The elements' type must implement the `__repr__()` for this to work.

        Parameters:
            U: The type of the elements in the list. Must implement the
              traits `Representable` and `Movable`.

        Returns:
            A string representation of the list.
        """
        return self.__str__()

    # ===-------------------------------------------------------------------===#
    # Methods
    # ===-------------------------------------------------------------------===#

    fn bytecount(self) -> Int:
        """Gets the bytecount of the List.

        Returns:
            The bytecount of the List.
        """
        return len(self) * size_of[T]()

    fn _realloc(mut self, new_capacity: Int):
        var new_data = LegacyUnsafePointer[T].alloc(new_capacity)

        _move_pointee_into_many_elements(
            dest=new_data,
            src=self.data,
            size=self.size,
        )

        if self.data:
            self.data.free()
        self.data = new_data
        self.capacity = new_capacity

    fn append(mut self, var value: T):
        """Appends a value to this list.

        Args:
            value: The value to append.
        """
        if self.size >= self.capacity:
            self._realloc(max(1, self.capacity * 2))
        (self.data + self.size).init_pointee_move(value^)
        self.size += 1

    fn insert(mut self, i: Int, var value: T):
        """Inserts a value to the list at the given index.
        `a.insert(len(a), value)` is equivalent to `a.append(value)`.

        Args:
            i: The index for the value.
            value: The value to insert.
        """
        debug_assert(i <= self.size, "insert index out of range")

        var normalized_idx = i
        if i < 0:
            normalized_idx = max(0, len(self) + i)

        var earlier_idx = len(self)
        var later_idx = len(self) - 1
        self.append(value^)

        for _ in range(normalized_idx, len(self) - 1):
            var earlier_ptr = self.data + earlier_idx
            var later_ptr = self.data + later_idx

            var tmp = earlier_ptr.take_pointee()
            earlier_ptr.init_pointee_move_from(later_ptr)
            later_ptr.init_pointee_move(tmp^)

            earlier_idx -= 1
            later_idx -= 1

    fn extend(mut self, var other: OwningList[T, *_]):
        """Extends this list by consuming the elements of `other`.

        Args:
            other: List whose elements will be added in order at the end of this list.
        """

        var final_size = len(self) + len(other)
        var other_original_size = len(other)

        self.reserve(final_size)

        # Defensively mark `other` as logically being empty, as we will be doing
        # consuming moves out of `other`, and so we want to avoid leaving `other`
        # in a partially valid state where some elements have been consumed
        # but are still part of the valid `size` of the list.
        #
        # That invalid intermediate state of `other` could potentially be
        # visible outside this function if a `__moveinit__()` constructor were
        # to throw (not currently possible AFAIK though) part way through the
        # logic below.
        other.size = 0

        var dest_ptr = self.data + len(self)

        for i in range(other_original_size):
            var src_ptr = other.data + i

            # This (TODO: optimistically) moves an element directly from the
            # `other` list into this list using a single `T.__moveinit()__`
            # call, without moving into an intermediate temporary value
            # (avoiding an extra redundant move constructor call).
            dest_ptr.init_pointee_move_from(src_ptr)

            dest_ptr = dest_ptr + 1

        # Update the size now that all new elements have been moved into this
        # list.
        self.size = final_size

    fn pop(mut self, i: Int = -1) -> T:
        """Pops a value from the list at the given index.

        Args:
            i: The index of the value to pop.

        Returns:
            The popped value.
        """
        debug_assert(-len(self) <= i < len(self), "pop index out of range")

        var normalized_idx = i
        if i < 0:
            normalized_idx += len(self)

        var ret_val = (self.data + normalized_idx).take_pointee()
        for j in range(normalized_idx + 1, self.size):
            (self.data + j - 1).init_pointee_move_from(self.data + j)
        self.size -= 1
        if self.size * 4 < self.capacity:
            if self.capacity > 1:
                self._realloc(self.capacity // 2)
        return ret_val^

    fn reserve(mut self, new_capacity: Int):
        """Reserves the requested capacity.

        If the current capacity is greater or equal, this is a no-op.
        Otherwise, the storage is reallocated and the date is moved.

        Args:
            new_capacity: The new capacity.
        """
        if self.capacity >= new_capacity:
            return
        self._realloc(new_capacity)

    fn resize(mut self, new_size: Int):
        """Resizes the list to the given new size.

        With no new value provided, the new size must be smaller than or equal
        to the current one. Elements at the end are discarded.

        Args:
            new_size: The new size.
        """
        if self.size < new_size:
            abort(
                "You are calling List.resize with a new_size bigger than the"
                " current size. If you want to make the List bigger, provide a"
                " value to fill the new slots with. If not, make sure the new"
                " size is smaller than the current size."
            )
        for i in range(new_size, self.size):
            (self.data + i).destroy_pointee()
        self.size = new_size
        self.reserve(new_size)

    # TODO: Remove explicit self type when issue 1876 is resolved.
    fn index[
        C: EqualityComparable & Movable, //
    ](ref self: OwningList[C, *_], value: C, start: Int = 0, stop: Optional[Int] = None,) raises -> Int:
        """
        Returns the index of the first occurrence of a value in a list
        restricted by the range given the start and stop bounds.

        ```mojo
        var my_list = List[Int](1, 2, 3)
        print(my_list.index(2)) # prints `1`
        ```

        Args:
            value: The value to search for.
            start: The starting index of the search, treated as a slice index
                (defaults to 0).
            stop: The ending index of the search, treated as a slice index
                (defaults to None, which means the end of the list).

        Parameters:
            C: The type of the elements in the list. Must implement the
                `EqualityComparable & Movable` trait.

        Returns:
            The index of the first occurrence of the value in the list.

        Raises:
            ValueError: If the value is not found in the list.
        """
        var start_normalized = start

        var stop_normalized: Int
        if stop is None:
            # Default end
            stop_normalized = len(self)
        else:
            stop_normalized = stop.value()

        if start_normalized < 0:
            start_normalized += len(self)
        if stop_normalized < 0:
            stop_normalized += len(self)

        start_normalized = _clip(start_normalized, 0, len(self))
        stop_normalized = _clip(stop_normalized, 0, len(self))

        for i in range(start_normalized, stop_normalized):
            if self[i] == value:
                return i
        raise "ValueError: Given element is not in list"

    fn clear(mut self):
        """Clears the elements in the list."""
        for i in range(self.size):
            (self.data + i).destroy_pointee()
        self.size = 0

    fn steal_data(mut self) -> LegacyUnsafePointer[T]:
        """Take ownership of the underlying pointer from the list.

        Returns:
            The underlying data.
        """
        var ptr = self.data
        self.data = LegacyUnsafePointer[T]()
        self.size = 0
        self.capacity = 0
        return ptr

    fn __getitem__(ref self, idx: Int) -> ref [self] T:
        """Gets the list element at the given index.

        Args:
            idx: The index of the element.

        Returns:
            A reference to the element at the given index.
        """

        var normalized_idx = idx

        debug_assert(
            -self.size <= normalized_idx < self.size,
            "index: ",
            normalized_idx,
            " is out of bounds for `List` of size: ",
            self.size,
        )
        if normalized_idx < 0:
            normalized_idx += len(self)

        return (self.data + normalized_idx)[]

    @always_inline
    fn unsafe_ptr(self) -> LegacyUnsafePointer[T]:
        """Retrieves a pointer to the underlying memory.

        Returns:
            The LegacyUnsafePointer to the underlying memory.
        """
        return self.data


fn _clip(value: Int, start: Int, end: Int) -> Int:
    return max(start, min(value, end))


fn _move_pointee_into_many_elements[T: Movable](dest: LegacyUnsafePointer[T], src: LegacyUnsafePointer[T], size: Int):
    for i in range(size):
        (dest + i).init_pointee_move_from(src + i)
        # (src + i).move_pointee_into(dest + i)
