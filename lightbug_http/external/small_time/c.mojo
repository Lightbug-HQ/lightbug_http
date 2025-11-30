# small_time library, courtesy @thatstoasty , 2025
# https://github.com/thatstoasty/small-time/
from sys import external_call
from sys.ffi import c_uchar
from memory import LegacyUnsafePointer, Pointer, stack_allocation


@register_passable("trivial")
struct TimeVal:
    """Time value."""

    var tv_sec: Int
    """Seconds."""
    var tv_usec: Int
    """Microseconds."""

    fn __init__(out self, tv_sec: Int = 0, tv_usec: Int = 0):
        """Initializes a new time value.

        Args:
            tv_sec: Seconds.
            tv_usec: Microseconds.
        """
        self.tv_sec = tv_sec
        self.tv_usec = tv_usec


@register_passable("trivial")
struct Tm:
    """C Tm struct."""

    var tm_sec: Int32
    """Seconds."""
    var tm_min: Int32
    """Minutes."""
    var tm_hour: Int32
    """Hour."""
    var tm_mday: Int32
    """Day of the month."""
    var tm_mon: Int32
    """Month."""
    var tm_year: Int32
    """Year minus 1900."""
    var tm_wday: Int32
    """Day of the week."""
    var tm_yday: Int32
    """Day of the year."""
    var tm_isdst: Int32
    """Daylight savings flag."""
    var tm_gmtoff: Int64
    """Localtime zone offset seconds."""

    fn __init__(out self):
        """Initializes a new time struct."""
        self.tm_sec = 0
        self.tm_min = 0
        self.tm_hour = 0
        self.tm_mday = 0
        self.tm_mon = 0
        self.tm_year = 0
        self.tm_wday = 0
        self.tm_yday = 0
        self.tm_isdst = 0
        self.tm_gmtoff = 0


fn gettimeofday() -> TimeVal:
    """Gets the current time. It's a wrapper around libc `gettimeofday`.

    Returns:
        Current time.
    """
    var tv = stack_allocation[1, TimeVal]()
    _ = external_call["gettimeofday", Int32](tv, 0)
    return tv.take_pointee()


fn time() -> Int:
    """Returns the current time in seconds since the Epoch.

    Returns:
        Current time in seconds.
    """
    var time = 0
    return external_call["time", Int](Pointer(to=time))


fn localtime(var tv_sec: Int) -> Tm:
    """Converts a time value to a broken-down local time.

    Args:
        tv_sec: Time value in seconds since the Epoch.

    Returns:
        Broken down local time.
    """
    return external_call["localtime", LegacyUnsafePointer[Tm]](LegacyUnsafePointer(to=tv_sec)).take_pointee()


fn strptime(time_str: String, time_format: String) -> Tm:
    """Parses a time string according to a format string.

    Args:
        time_str: Time string.
        time_format: Time format string.

    Returns:
        Broken down time.
    """
    var tm = stack_allocation[1, Tm]()
    _ = external_call["strptime", NoneType, LegacyUnsafePointer[c_uchar], LegacyUnsafePointer[c_uchar], LegacyUnsafePointer[Tm]](
        time_str.unsafe_ptr(), time_format.unsafe_ptr(), tm
    )
    return tm.take_pointee()


fn gmtime(var tv_sec: Int) -> Tm:
    """Converts a time value to a broken-down UTC time.

    Args:
        tv_sec: Time value in seconds since the Epoch.

    Returns:
        Broken down UTC time.
    """
    return external_call["gmtime", LegacyUnsafePointer[Tm]](Pointer(to=tv_sec)).take_pointee()
