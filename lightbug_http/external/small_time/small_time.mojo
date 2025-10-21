# small_time library, courtesy @thatstoasty , 2025
# https://github.com/thatstoasty/small-time/ 
from collections import InlineArray, Optional
import lightbug_http.external.small_time.c
import lightbug_http.external.small_time.time_zone
from lightbug_http.external.small_time.time_delta import TimeDelta
from lightbug_http.external.small_time.formatter import formatter


alias _DI400Y = 146097
"""Number of days in 400 years."""
alias _DI100Y = 36524
"""Number of days in 100 years."""
alias _DI4Y = 1461
"""Number of days in 4 years."""
alias _DAYS_IN_MONTH = InlineArray[Int, 13](-1, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)
"""Number of days in each month, not counting leap years."""
alias _DAYS_BEFORE_MONTH = InlineArray[Int, 13](
    -1, 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334
)  # -1 is a placeholder for indexing purposes.
"""Number of days before each month in a common year."""


fn _is_leap(year: Int) -> Bool:
    """If the year is a leap year.
    
    Args:
        year: The year to check.
    
    Returns:
        True if the year is a leap year, False otherwise.
    
    Notes:
        A year is a leap year if it is divisible by 4, but not by 100, unless it is divisible by 400.
    """
    return year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)


fn _days_before_year(year: Int) -> Int:
    """Number of days before January 1st of year.

    Args:
        year: The year to check.
    
    Returns:
        Number of days before January 1st of year.
    
    Notes:
        year -> number of days before January 1st of year.
    """
    var y = year - 1
    return y * 365 + y // 4 - y // 100 + y // 400


fn _days_in_month(year: Int, month: Int) -> Int:
    """Number of days in a month in a year.

    Args:
        year: The year to check.
        month: The month to check.
    
    Returns:
        Number of days in that month in that year.
    
    Notes:
        year, month -> number of days in that month in that year.
    """
    if month == 2 and _is_leap(year):
        return 29
    return _DAYS_IN_MONTH[month]


fn _days_before_month(year: Int, month: Int) -> Int:
    """Number of days in year preceding first day of month.

    Args:
        year: The year to check.
        month: The month to check.
    
    Returns:
        Number of days in year preceding first day of month.
    
    Notes:
        year, month -> number of days in year preceding first day of month.
    """
    if month > 2 and _is_leap(year):
        return _DAYS_BEFORE_MONTH[month] + 1
    return _DAYS_BEFORE_MONTH[month]


fn _ymd2ord(year: Int, month: Int, day: Int) -> Int:
    """Convert year, month, day to ordinal, considering 01-Jan-0001 as day 1.
    
    Args:
        year: The year to check.
        month: The month to check.
        day: The day to check.
    
    Returns:
        Ordinal, considering 01-Jan-0001 as day 1.
    """
    return _days_before_year(year) + _days_before_month(year, month) + day


alias MAX_TIMESTAMP: Int = 32503737600
"""Maximum timestamp."""
alias MAX_TIMESTAMP_MS = MAX_TIMESTAMP * 1000
"""Maximum timestamp in milliseconds."""
alias MAX_TIMESTAMP_US = MAX_TIMESTAMP * 1_000_000
"""Maximum timestamp in microseconds."""


fn normalize_timestamp(var timestamp: Float64) raises -> Float64:
    """Normalize millisecond and microsecond timestamps into normal timestamps.
    
    Args:
        timestamp: The timestamp to normalize.
    
    Returns:
        The normalized timestamp.
    
    Raises:
        Error: If the timestamp is too large.
    """
    if timestamp > MAX_TIMESTAMP:
        if timestamp < MAX_TIMESTAMP_MS:
            timestamp /= 1000
        elif timestamp < MAX_TIMESTAMP_US:
            timestamp /= 1_000_000
        else:
            raise Error("The specified timestamp " + String(timestamp) + "is too large.")
    return timestamp


fn now(*, utc: Bool = False) raises -> SmallTime:
    """Return the current time in UTC or local time.

    Args:
        utc: If True, return the current time in UTC. Otherwise, return the current time in local time.
    
    Returns:
        The current time.
    """
    return from_timestamp(c.gettimeofday(), utc)


fn _validate_timestamp(tm: c.Tm, time_val: c.TimeVal, time_zone: TimeZone) raises -> SmallTime:
    """Validate the timestamp.

    Args:
        tm: The time struct.
        time_val: The time value.
        time_zone: The time zone.
    
    Returns:
        The validated timestamp.
    
    Raises:
        Error: If the timestamp is invalid.
    """
    var year = Int(tm.tm_year) + 1900
    if not -1 < year < 10000:
        raise Error("The year parsed out from the timestamp is too large or negative. Received: ", year)

    var month = Int(tm.tm_mon) + 1
    if not -1 < month < 13:
        raise Error("The month parsed out from the timestamp is too large or negative. Received: ", month)

    var day = Int(tm.tm_mday)
    if not -1 < day < 32:
        raise Error(
            "The day of the month parsed out from the timestamp is too large or negative. Received: ", day
        )

    var hours = Int(tm.tm_hour)
    if not -1 < hours < 25:
        raise Error("The hour parsed out from the timestamp is too large or negative. Received: ", hours)

    var minutes = Int(tm.tm_min)
    if not -1 < minutes < 61:
        raise Error("The minutes parsed out from the timestamp is too large or negative. Received: ", minutes)

    var seconds = Int(tm.tm_sec)
    if not -1 < seconds < 61:
        raise Error(
            "The day of the month parsed out from the timestamp is too large or negative. Received: ", seconds
        )

    var microseconds = time_val.tv_usec
    if microseconds < 0:
        raise Error("Received negative microseconds. Received: ", microseconds)

    return SmallTime(
        year,
        month,
        day,
        hours,
        minutes,
        seconds,
        microseconds,
        time_zone,
    )


fn from_timestamp(t: c.TimeVal, utc: Bool) raises -> SmallTime:
    """Create a SmallTime instance from a timestamp.

    Args:
        t: The timestamp.
        utc: If True, the timestamp is in UTC. Otherwise, the timestamp is in local time.
    
    Returns:
        The SmallTime instance.
    
    Raises:
        Error: If the timestamp is invalid.
    """
    if utc:
        return _validate_timestamp(c.gmtime(t.tv_sec), t, TimeZone(0, "UTC"))

    var tm = c.localtime(t.tv_sec)
    var tz = TimeZone(Int(tm.tm_gmtoff), "local")
    return _validate_timestamp(tm, t, tz)


fn from_timestamp(timestamp: Float64, *, utc: Bool = False) raises -> SmallTime:
    """Create a SmallTime instance from a timestamp.

    Args:
        timestamp: The timestamp.
        utc: If True, the timestamp is in UTC. Otherwise, the timestamp is in local time.
    
    Returns:
        The SmallTime instance.
    
    Raises:
        Error: If the timestamp is invalid.
    """
    var timestamp_ = normalize_timestamp(timestamp)
    return from_timestamp(c.TimeVal(Int(timestamp_)), utc)


fn strptime(date_str: String, fmt: String, tzinfo: TimeZone = TimeZone()) raises -> SmallTime:
    """Create a SmallTime instance from a date string and format,
    in the style of `datetime.strptime`.  Optionally replaces the parsed time_zone.

    Args:
        date_str: The date string.
        fmt: The format string.
        tzinfo: The time zone.
    
    Returns:
        The SmallTime instance.
    
    Raises:
        Error: If the timestamp is invalid.

    Examples:
    ```mojo
    from lightbug_http.external.small_time.small_time import strptime
    print(strptime('20-01-2019 15:49:10', '%d-%m-%Y %H:%M:%S'))
    ```
    .
    """
    var tm = c.strptime(date_str, fmt)
    var tz = TimeZone(Int(tm.tm_gmtoff)) if not tzinfo else tzinfo
    return _validate_timestamp(tm, c.TimeVal(), tz)


fn strptime(date_str: String, fmt: String, tz_str: String) raises -> SmallTime:
    """Create a SmallTime instance from a date string and format,
    in the style of `datetime.strptime`.  Optionally replaces the parsed time_zone.

    Args:
        date_str: The date string.
        fmt: The format string.
        tz_str: The time zone.
    
    Returns:
        The SmallTime instance.
    
    Raises:
        Error: If the timestamp is invalid.

    Examples:
    ```mojo
    from lightbug_http.external.small_time.small_time import strptime
    print(strptime('20-01-2019 15:49:10', '%d-%m-%Y %H:%M:%S'))
    ```
    .
    """
    return strptime(date_str, fmt, time_zone.from_utc(tz_str))


fn from_ordinal(ordinal: Int) -> SmallTime:
    """Construct a SmallTime from a proleptic Gregorian ordinal.

    Args:
        ordinal: The proleptic Gregorian ordinal.
    
    Returns:
        The SmallTime instance.
    
    Notes:
        January 1 of year 1 is day 1.  Only the year, month and day are
        non-zero in the result.
    """
    var n = ordinal
    # n is a 1-based index, starting at 1-Jan-1.  The pattern of leap years
    # repeats exactly every 400 years.  The basic strategy is to find the
    # closest 400-year boundary at or before n, then work with the offset
    # from that boundary to n.  Life is much clearer if we subtract 1 from
    # n first -- then the values of n at 400-year boundaries are exactly
    # those divisible by _DI400Y:
    #
    #     D  M   Y            n              n-1
    #     -- --- ----        ----------     ----------------
    #     31 Dec -400        -_DI400Y       -_DI400Y -1
    #      1 Jan -399         -_DI400Y +1   -_DI400Y      400-year boundary
    #     ...
    #     30 Dec  000        -1             -2
    #     31 Dec  000         0             -1
    #      1 Jan  001         1              0            400-year boundary
    #      2 Jan  001         2              1
    #      3 Jan  001         3              2
    #     ...
    #     31 Dec  400         _DI400Y        _DI400Y -1
    #      1 Jan  401         _DI400Y +1     _DI400Y      400-year boundary
    n -= 1
    var n400 = n // _DI400Y
    n = n % _DI400Y
    var year = n400 * 400 + 1  # ..., -399, 1, 401, ...

    # Now n is the (non-negative) offset, in days, from January 1 of year, to
    # the desired date.  Now compute how many 100-year cycles precede n.
    # Note that it's possible for n100 to equal 4!  In that case 4 full
    # 100-year cycles precede the desired day, which implies the desired
    # day is December 31 at the end of a 400-year cycle.
    var n100 = n // _DI100Y
    n = n % _DI100Y

    # Now compute how many 4-year cycles precede it.
    var n4 = n // _DI4Y
    n = n % _DI4Y

    # And now how many single years.  Again n1 can be 4, and again meaning
    # that the desired day is December 31 at the end of the 4-year cycle.
    var n1 = n // 365
    n = n % 365

    year += n100 * 100 + n4 * 4 + n1
    if n1 == 4 or n100 == 4:
        return SmallTime(year - 1, 12, 31)

    # Now the year is correct, and n is the offset from January 1.  We find
    # the month via an estimate that's either exact or one too large.
    var leap_year = n1 == 3 and (n4 != 24 or n100 == 3)
    var month = (n + 50) >> 5
    var preceding: Int
    if month > 2 and leap_year:
        preceding = _DAYS_BEFORE_MONTH[month] + 1
    else:
        preceding = _DAYS_BEFORE_MONTH[month]
    if preceding > n:  # estimate is too large
        month -= 1
        if month == 2 and leap_year:
            preceding -= _DAYS_BEFORE_MONTH[month] + 1
        else:
            preceding -= _DAYS_BEFORE_MONTH[month]
    n -= preceding

    # Now the year and month are correct, and n is the offset from the
    # start of that month:  we're done!
    return SmallTime(year, month, n + 1)


struct SmallTime(Stringable, Writable, Representable, Copyable, Movable, ImplicitlyCopyable):
    """Datetime representation."""
    var year: Int
    """Year."""
    var month: Int
    """Month."""
    var day: Int
    """Day."""
    var hour: Int
    """Hour."""
    var minute: Int
    """Minute."""
    var second: Int
    """Second."""
    var microsecond: Int
    """Microsecond."""
    var tz: TimeZone
    """Time zone."""

    fn __init__(
        out self,
        year: Int,
        month: Int,
        day: Int,
        hour: Int = 0,
        minute: Int = 0,
        second: Int = 0,
        microsecond: Int = 0,
        tz: TimeZone = TimeZone(),
    ):
        """Initializes a new SmallTime instance.

        Args:
            year: Year.
            month: Month.
            day: Day.
            hour: Hour.
            minute: Minute.
            second: Second.
            microsecond: Microsecond.
            tz: Time zone.
        """
        self.year = year
        self.month = month
        self.day = day
        self.hour = hour
        self.minute = minute
        self.second = second
        self.microsecond = microsecond
        self.tz = tz

    fn format(self, fmt: String = "YYYY-MM-DD HH:mm:ss ZZ") -> String:
        """Returns a string representation of the `SmallTime`
        formatted according to the provided format string.

        Args:
            fmt: The format string.

        Returns:
            The formatted string.
        
        Examples:
        ```mojo
        import small_time
        var m = small_time.now()
        print(m.format('YYYY-MM-DD HH:mm:ss ZZ')) #'2013-05-09 03:56:47 -00:00'
        print(m.format('MMMM DD, YYYY')) #'May 09, 2013'
        print(m.format()) #'2013-05-09 03:56:47 -00:00'
        ```
        .
        """
        return materialize[formatter]().format(self, fmt)

    fn isoformat[timespec: String = "auto"](self, sep: String = "T") -> String:
        """Return the time formatted according to ISO.

        Parameters:
            timespec: The number of additional terms of the time to include.

        Args:
            sep: The separator between date and time.
        
        Returns:
            The formatted string.
        
        Notes:
            The full format looks like 'YYYY-MM-DD HH:MM:SS.mmmmmm'.

            If self.tzinfo is not None, the UTC offset is also attached, giving
            giving a full format of 'YYYY-MM-DD HH:MM:SS.mmmmmm+HH:MM'.

            Optional argument sep specifies the separator between date and
            time, default 'T'.

            The optional argument timespec specifies the number of additional
            terms of the time to include. Valid options are 'auto', 'hours',
            'minutes', 'seconds', 'milliseconds' and 'microseconds'.
        """
        alias valid = InlineArray[String, 6]("auto", "hours", "minutes", "seconds", "milliseconds", "microseconds")
        """Valid timespec values."""
        constrained[
            timespec in valid,
            msg="timespec must be one of the following: 'auto', 'hours', 'minutes', 'seconds', 'milliseconds', 'microseconds'",
        ]()
        var date_str = String(
            String(self.year).rjust(4, "0"), "-", String(self.month).rjust(2, "0"), "-" + String(self.day).rjust(2, "0")
        )
        var time_str = String("")

        @parameter
        if timespec == "auto" or timespec == "microseconds":
            time_str = String(
                String(self.hour).rjust(2, "0"), 
                ":",
                String(self.minute).rjust(2, "0"),
                ":",
                String(self.second).rjust(2, "0"),
                ".",
                String(self.microsecond).rjust(6, "0")
            )
        elif timespec == "milliseconds":
            time_str = String(
                String(self.hour).rjust(2, "0"),
                ":",
                String(self.minute).rjust(2, "0"),
                ":",
                String(self.second).rjust(2, "0"),
                ".",
                String(self.microsecond // 1000).rjust(3, "0")
            )
        elif timespec == "seconds":
            time_str = String(
                String(self.hour).rjust(2, "0"),
                ":",
                String(self.minute).rjust(2, "0"),
                ":",
                String(self.second).rjust(2, "0")
            )
        elif timespec == "minutes":
            time_str = String(String(self.hour).rjust(2, "0"), ":", String(self.minute).rjust(2, "0"))
        elif timespec == "hours":
            time_str = String(self.hour).rjust(2, "0")

        if not self.tz:
            return sep.join(date_str, time_str)
        else:
            return sep.join(date_str, time_str) + self.tz.format()

    fn to_ordinal(self) -> Int:
        """Return proleptic Gregorian ordinal for the year, month and day.

        Returns:
            Proleptic Gregorian ordinal for the year, month and day.
        
        Notes:
            January 1 of year 1 is day 1.  Only the year, month and day values
            contribute to the result.
        """
        return _ymd2ord(self.year, self.month, self.day)

    fn iso_weekday(self) -> Int:
        """Returns day of the week.

        Returns:
            Day of the week, where Monday == 1 ... Sunday == 7.
        """
        return self.to_ordinal() % 7 or 7

    fn __str__(self) -> String:
        """Return the string representation of the `SmallTime` instance.
        
        Returns:
            The string representation.
        """
        return self.isoformat()
    
    fn __repr__(self) -> String:
        """Return the string representation of the `SmallTime` instance.
        
        Returns:
            The string representation.
        """
        return String.write(self)

    fn __sub__(self, other: Self) -> TimeDelta:
        """Subtract two `SmallTime` instances.

        Args:
            other: The other `SmallTime` instance.
        
        Returns:
            The time difference.
        """
        var days1 = self.to_ordinal()
        var days2 = other.to_ordinal()
        var secs1 = self.second + self.minute * 60 + self.hour * 3600
        var secs2 = other.second + other.minute * 60 + other.hour * 3600
        var base = TimeDelta(days1 - days2, secs1 - secs2, self.microsecond - other.microsecond)
        return base
    
    fn write_to[W: Writer, //](self, mut writer: W):
        """Writes a representation of the `SmallTime` instance to a writer.

        Parameters:
            W: The type of writer to write the contents to.

        Args:
            writer: The writer to write the contents to.
        """
        @parameter
        fn write_optional(opt: Optional[String]):
            if opt:
                writer.write(repr(opt.value()))
            else:
                writer.write(repr(None))

        writer.write("SmallTime(",
        "year=", self.year,
        ", month=", self.month,
        ", day=", self.day,
        ", hour=", self.hour,
        ", minute=", self.minute,
        ", second=", self.second,
        ", microsecond=", self.microsecond,
        )
        writer.write(", tz=", "TimeZone(",
        "offset=", self.tz.offset,
        ", name=")
        write_optional(self.tz.name)
        writer.write(")")
        writer.write(")")
