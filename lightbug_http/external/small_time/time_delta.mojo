# small_time library, courtesy @thatstoasty , 2025
# https://github.com/thatstoasty/small-time/
comptime SECONDS_OF_DAY = 24 * 3600


@register_passable("trivial")
struct TimeDelta(Stringable):
    """Time delta."""

    var days: Int
    """Days."""
    var seconds: Int
    """Seconds."""
    var microseconds: Int
    """Microseconds."""

    fn __init__(
        out self,
        days: Int = 0,
        seconds: Int = 0,
        microseconds: Int = 0,
        milliseconds: Int = 0,
        minutes: Int = 0,
        hours: Int = 0,
        weeks: Int = 0,
    ):
        """Initializes a new time delta.

        Args:
            days: Days.
            seconds: Seconds.
            microseconds: Microseconds.
            milliseconds: Milliseconds.
            minutes: Minutes.
            hours: Hours.
            weeks: Weeks.
        """
        self.days = 0
        self.seconds = 0
        self.microseconds = 0

        var days_ = days
        var seconds_ = seconds
        var microseconds_ = microseconds

        # Normalize everything to days, seconds, microseconds.
        days_ += weeks * 7
        seconds_ += minutes * 60 + hours * 3600
        microseconds_ += milliseconds * 1000

        self.days = days_
        days_ = seconds_ // SECONDS_OF_DAY
        seconds_ = seconds_ % SECONDS_OF_DAY
        self.days += days_
        self.seconds += seconds_

        seconds_ = microseconds_ // 1000000
        microseconds_ = microseconds_ % 1000000
        days_ = seconds_ // SECONDS_OF_DAY
        seconds_ = seconds_ % SECONDS_OF_DAY
        self.days += days_
        self.seconds += seconds_

        seconds_ = microseconds_ // 1000000
        self.microseconds = microseconds_ % 1000000
        self.seconds += seconds_
        days_ = self.seconds // SECONDS_OF_DAY
        self.seconds = self.seconds % SECONDS_OF_DAY
        self.days += days_

    fn __str__(self) -> String:
        """String representation of the duration.

        Returns:
            String representation of the duration.
        """
        var mm = self.seconds // 60
        var ss = String(self.seconds % 60)
        var hh = String(mm // 60)
        mm = mm % 60
        var s = String(hh, ":", String(mm).rjust(2, "0"), ":", ss.rjust(2, "0"))
        if self.days:
            if abs(self.days) != 1:
                s = String(self.days, " days, ", s)
            else:
                s = String(self.days, " day, ", s)
        if self.microseconds:
            s.write(String(self.microseconds).rjust(6, "0"))
        return s^

    fn total_seconds(self) -> Float64:
        """Total seconds in the duration.

        Returns:
            Total seconds in the duration.
        """
        return ((self.days * 86400 + self.seconds) * 10**6 + self.microseconds) / 10**6

    fn __add__(self, other: Self) -> Self:
        """Adds two time deltas.

        Args:
            other: Time delta to add.

        Returns:
            Sum of the two time deltas.
        """
        return Self(
            self.days + other.days,
            self.seconds + other.seconds,
            self.microseconds + other.microseconds,
        )

    fn __radd__(self, other: Self) -> Self:
        """Adds two time deltas.

        Args:
            other: Time delta to add.

        Returns:
            Sum of the two time deltas.
        """
        return self.__add__(other)

    fn __sub__(self, other: Self) -> Self:
        """Subtracts two time deltas.

        Args:
            other: Time delta to subtract.

        Returns:
            Difference of the two time deltas.
        """
        return Self(
            self.days - other.days,
            self.seconds - other.seconds,
            self.microseconds - other.microseconds,
        )

    fn __rsub__(self, other: Self) -> Self:
        """Subtracts two time deltas.

        Args:
            other: Time delta to subtract.

        Returns:
            Difference of the two time deltas.
        """
        return Self(
            other.days - self.days,
            other.seconds - self.seconds,
            other.microseconds - self.microseconds,
        )

    fn __neg__(self) -> Self:
        """Negates the time delta.

        Returns:
            Negated time delta.
        """
        return Self(-self.days, -self.seconds, -self.microseconds)

    fn __pos__(self) -> Self:
        """Returns the time delta.

        Returns:
            Time delta.
        """
        return self

    def __abs__(self) -> Self:
        """Returns the absolute value of the time delta.

        Returns:
            Absolute value of the time delta.
        """
        if self.days < 0:
            return -self
        else:
            return self

    fn __mul__(self, other: Int) -> Self:
        """Multiplies the time delta by a scalar.

        Args:
            other: Scalar to multiply by.

        Returns:
            Scaled time delta.
        """
        return Self(
            self.days * other,
            self.seconds * other,
            self.microseconds * other,
        )

    fn __rmul__(self, other: Int) -> Self:
        """Multiplies the time delta by a scalar.

        Args:
            other: Scalar to multiply by.

        Returns:
            Scaled time delta.
        """
        return self.__mul__(other)

    fn _to_microseconds(self) -> Int:
        """Converts the time delta to microseconds.

        Returns:
            Time delta in microseconds.
        """
        return (self.days * SECONDS_OF_DAY + self.seconds) * 1000000 + self.microseconds

    fn __mod__(self, other: Self) -> Self:
        """Returns the remainder of the division of two time deltas.

        Args:
            other: Time delta to divide by.

        Returns:
            Remainder of the division of two time deltas.
        """
        return Self(0, 0, self._to_microseconds() % other._to_microseconds())

    fn __eq__(self, other: Self) -> Bool:
        """Checks if two time deltas are equal.

        Args:
            other: Time delta to compare with.

        Returns:
            True if the time deltas are equal, False otherwise.
        """
        return self.days == other.days and self.seconds == other.seconds and self.microseconds == other.microseconds

    fn __le__(self, other: Self) -> Bool:
        """Checks if the time delta is less than or equal to the other time delta.

        Args:
            other: Time delta to compare with.

        Returns:
            True if the time delta is less than or equal to the other time delta, False otherwise.
        """
        if self.days < other.days:
            return True
        elif self.days == other.days:
            if self.seconds < other.seconds:
                return True
            elif self.seconds == other.seconds and self.microseconds <= other.microseconds:
                return True
        return False

    fn __lt__(self, other: Self) -> Bool:
        """Checks if the time delta is less than the other time delta.

        Args:
            other: Time delta to compare with.

        Returns:
            True if the time delta is less than the other time delta, False otherwise.
        """
        if self.days < other.days:
            return True
        elif self.days == other.days:
            if self.seconds < other.seconds:
                return True
            elif self.seconds == other.seconds and self.microseconds < other.microseconds:
                return True
        return False

    fn __ge__(self, other: Self) -> Bool:
        """Checks if the time delta is greater than or equal to the other time delta.

        Args:
            other: Time delta to compare with.

        Returns:
            True if the time delta is greater than or equal to the other time delta, False otherwise.
        """
        return not self.__lt__(other)

    fn __gt__(self, other: Self) -> Bool:
        """Checks if the time delta is greater than the other time delta.

        Args:
            other: Time delta to compare with.

        Returns:
            True if the time delta is greater than the other time delta, False otherwise.
        """
        return not self.__le__(other)

    fn __bool__(self) -> Bool:
        """Checks if the time delta is non-zero.

        Returns:
            True if the time delta is non-zero, False otherwise.
        """
        return self.days != 0 or self.seconds != 0 or self.microseconds != 0


comptime MIN = TimeDelta(-99999999)
"""Minimum time delta."""
comptime MAX = TimeDelta(days=99999999)
"""Maximum time delta."""
comptime RESOLUTION = TimeDelta(microseconds=1)
"""Resolution of the time delta."""
