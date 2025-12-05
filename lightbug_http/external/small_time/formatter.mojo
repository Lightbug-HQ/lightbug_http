# small_time library, courtesy @thatstoasty , 2025
# https://github.com/thatstoasty/small-time/
from collections import InlineArray
from collections.string import StringSlice

from lightbug_http.external.small_time.time_zone import UTC_TZ
from utils import StaticTuple


comptime MONTH_NAMES = InlineArray[String, 13](
    "",
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
)
"""The full month names."""

comptime MONTH_ABBREVIATIONS = InlineArray[String, 13](
    "",
    "Jan",
    "Feb",
    "Mar",
    "Apr",
    "May",
    "Jun",
    "Jul",
    "Aug",
    "Sep",
    "Oct",
    "Nov",
    "Dec",
)
"""The month name abbreviations."""

comptime DAY_NAMES = InlineArray[String, 8](
    "",
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
    "Sunday",
)
"""The full day names."""
comptime DAY_ABBREVIATIONS = InlineArray[String, 8]("", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
"""The day name abbreviations."""
comptime formatter = _Formatter()
"""Default formatter instance."""


struct _Formatter(ImplicitlyCopyable):
    """SmallTime formatter."""

    var _sub_chrs: StaticTuple[Int, 128]
    """Substitution characters."""

    fn __init__(out self):
        """Initializes a new formatter."""
        self._sub_chrs = StaticTuple[Int, 128]()
        for i in range(128):
            self._sub_chrs[i] = 0
        self._sub_chrs[_Y] = 4
        self._sub_chrs[_M] = 4
        self._sub_chrs[_D] = 2
        self._sub_chrs[_d] = 4
        self._sub_chrs[_H] = 2
        self._sub_chrs[_h] = 2
        self._sub_chrs[_m] = 2
        self._sub_chrs[_s] = 2
        self._sub_chrs[_S] = 6
        self._sub_chrs[_Z] = 3
        self._sub_chrs[_A] = 1
        self._sub_chrs[_a] = 1

    fn format(self, m: SmallTime, fmt: String) -> String:
        """Formats the given time value using the specified format string.
        "YYYY[abc]MM" -> replace("YYYY") + "abc" + replace("MM")

        Args:
            m: Time value.
            fmt: Format string.

        Returns:
            Formatted time string.
        """
        if len(fmt) == 0:
            return ""

        var format = fmt.as_string_slice()
        var result: String = ""
        var in_bracket = False
        var start = 0

        for i in range(len(format)):
            if format[i] == "[":
                if in_bracket:
                    result.write("[")
                else:
                    in_bracket = True

                result.write(self.replace(m, format[start:i]))

                start = i + 1
            elif format[i] == "]":
                if in_bracket:
                    result.write(format[start:i])
                    in_bracket = False
                else:
                    result.write(format[start:i])
                    result.write("]")
                start = i + 1

        if in_bracket:
            result.write("[")

        if start < len(format):
            result.write(self.replace(m, format[start:]))
        return result

    fn replace(self, m: SmallTime, fmt: StringSlice) -> String:
        """Replaces the tokens in the given format string with the corresponding values.

        Args:
            m: Time value.
            fmt: Format string.

        Returns:
            Formatted time string.
        """
        if len(fmt) == 0:
            return ""

        var result: String = ""
        var matched_byte = 0
        var matched_count = 0
        for i in range(len(fmt)):
            var c = ord(fmt[i])

            # If the current character is not a token, add it to the result.
            if c > 127 or self._sub_chrs[c] == 0:
                if matched_byte > 0:
                    result += self.replace_token(m, matched_byte, matched_count)
                    matched_byte = 0
                result += fmt[i]
                continue

            # If the current character is the same as the previous one, increment the count.
            if c == matched_byte:
                matched_count += 1
                continue

            # If the current character is different from the previous one, replace the previous tokens
            # and move onto the next token to track.
            result += self.replace_token(m, matched_byte, matched_count)
            matched_byte = c
            matched_count = 1

        # If no tokens were found, append an empty string and return the original.
        if matched_byte > 0:
            result += self.replace_token(m, matched_byte, matched_count)
        return result

    fn replace_token(self, m: SmallTime, token: Int, token_count: Int) -> String:
        if token == _Y:
            if token_count == 1:
                return "Y"
            if token_count == 2:
                return String(m.year).rjust(4, "0")[2:4]
            if token_count == 4:
                return String(m.year).rjust(4, "0")
        elif token == _M:
            if token_count == 1:
                return String(m.month)
            if token_count == 2:
                return String(m.month).rjust(2, "0")
            if token_count == 3:
                return MONTH_ABBREVIATIONS[m.month]
            if token_count == 4:
                return MONTH_NAMES[m.month]
        elif token == _D:
            if token_count == 1:
                return String(m.day)
            if token_count == 2:
                return String(m.day).rjust(2, "0")
        elif token == _H:
            if token_count == 1:
                return String(m.hour)
            if token_count == 2:
                return String(m.hour).rjust(2, "0")
        elif token == _h:
            var h_12 = m.hour
            if m.hour > 12:
                h_12 -= 12
            if token_count == 1:
                return String(h_12)
            if token_count == 2:
                return String(h_12).rjust(2, "0")
        elif token == _m:
            if token_count == 1:
                return String(m.minute)
            if token_count == 2:
                return String(m.minute).rjust(2, "0")
        elif token == _s:
            if token_count == 1:
                return String(m.second)
            if token_count == 2:
                return String(m.second).rjust(2, "0")
        elif token == _S:
            if token_count == 1:
                return String(m.microsecond // 100000)
            if token_count == 2:
                return String(m.microsecond // 10000).rjust(2, "0")
            if token_count == 3:
                return String(m.microsecond // 1000).rjust(3, "0")
            if token_count == 4:
                return String(m.microsecond // 100).rjust(4, "0")
            if token_count == 5:
                return String(m.microsecond // 10).rjust(5, "0")
            if token_count == 6:
                return String(m.microsecond).rjust(6, "0")
        elif token == _d:
            if token_count == 1:
                return String(m.iso_weekday())
            if token_count == 3:
                return DAY_ABBREVIATIONS[m.iso_weekday()]
            if token_count == 4:
                return DAY_NAMES[m.iso_weekday()]
        elif token == _Z:
            if token_count == 3:
                return String(UTC_TZ) if not m.tz else String(m.tz)
            var separator = "" if token_count == 1 else ":"
            if not m.tz:
                return UTC_TZ.format(separator)
            else:
                return m.tz.format(separator)

        elif token == _a:
            return "am" if m.hour < 12 else "pm"
        elif token == _A:
            return "AM" if m.hour < 12 else "PM"
        return ""


comptime _Y = ord("Y")
comptime _M = ord("M")
comptime _D = ord("D")
comptime _d = ord("d")
comptime _H = ord("H")
comptime _h = ord("h")
comptime _m = ord("m")
comptime _s = ord("s")
comptime _S = ord("S")
comptime _X = ord("X")
comptime _x = ord("x")
comptime _Z = ord("Z")
comptime _A = ord("A")
comptime _a = ord("a")
