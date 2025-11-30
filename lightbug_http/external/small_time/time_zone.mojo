# small_time library, courtesy @thatstoasty , 2025
# https://github.com/thatstoasty/small-time/
from collections import Optional
import lightbug_http.external.small_time.c

alias UTC = "UTC"
alias UTC_TZ = TimeZone(0, UTC)
"""UTC Timezone."""

alias DASH = "-"
alias PLUS = "+"
alias COLON = ":"


fn local() -> TimeZone:
    """Returns the local timezone.

    Returns:
        Local timezone.
    """
    var local_t = c.localtime(0)
    return TimeZone(Int(local_t.tm_gmtoff), "local")


fn _is_numeric(c: Byte) -> Bool:
    """Checks if a character is numeric.

    Args:
        c: Character.

    Returns:
        True if the character is numeric, False otherwise.
    """
    return c >= ord("0") and c <= ord("9")


fn from_utc(utc_str: String) raises -> TimeZone:
    """Creates a timezone from a string.

    Args:
        utc_str: UTC string.

    Returns:
        Timezone.

    Raises:
        Error: If the UTC string is invalid.
    """
    var timezone = utc_str.as_string_slice()
    if len(timezone) == 0:
        raise Error("utc_str is empty")

    if timezone == "utc" or timezone == "UTC" or timezone == "Z":
        return TimeZone(0, String("utc"))

    var i = 0
    # Skip the UTC prefix.
    if len(timezone) > 3 and timezone[0:3] == UTC:
        i = 3

    var sign = -1 if timezone[i] == DASH else 1
    if timezone[i] == PLUS or timezone[i] == DASH:
        i += 1

    if len(timezone) < i + 2 or not _is_numeric(ord(timezone[i])) or not _is_numeric(ord(timezone[i + 1])):
        raise Error("utc_str format is invalid")
    var hours = atol(timezone[i : i + 2])
    i += 2

    var minutes: Int
    if len(timezone) <= i:
        minutes = 0
    elif len(timezone) == i + 3 and timezone[i] == COLON:
        minutes = atol(timezone[i + 1 : i + 3])
    elif len(timezone) == i + 2 and _is_numeric(ord(timezone[i])):
        minutes = atol(timezone[i : i + 2])
    else:
        raise Error("utc_str format is invalid")

    var offset = sign * (hours * 3600 + minutes * 60)
    return TimeZone(offset)


@fieldwise_init
struct TimeZone(ImplicitlyCopyable, Stringable):
    """Timezone."""

    var offset: Int
    """Offset in seconds."""
    var name: Optional[String]
    """Name of the timezone."""

    fn __init__(out self, offset: Int = 0, name: String = "utc"):
        """Initializes a new timezone.

        Args:
            offset: Offset in seconds.
            name: Name of the timezone.
        """
        self.offset = offset
        self.name = name

    fn __str__(self) -> String:
        """String representation of the timezone.

        Returns:
            String representation.
        """
        if self.name:
            return self.name.value()
        return ""

    fn __bool__(self) -> Bool:
        """Checks if the timezone is valid.

        Returns:
            True if the timezone is valid, False otherwise.
        """
        return self.name.__bool__()

    fn format(self, sep: String = ":") -> String:
        """Formats the timezone.

        Args:
            sep: Separator between hours and minutes.

        Returns:
            Formatted timezone.
        """
        var sign: String
        var offset_abs: Int
        if self.offset < 0:
            sign = "-"
            offset_abs = -self.offset
        else:
            sign = "+"
            offset_abs = self.offset
        var hh = String(offset_abs // 3600)
        var mm = String(offset_abs % 3600)
        return String(sign, hh.rjust(2, "0"), sep, mm.rjust(2, "0"))
