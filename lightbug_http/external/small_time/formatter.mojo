# small_time library, courtesy @thatstoasty , 2025
# https://github.com/thatstoasty/small-time/
from collections import InlineArray
from collections.string import StringSlice
from utils import StaticTuple
from lightbug_http.external.small_time.time_zone import UTC_TZ


trait Formattable:
    fn replace_token(self, token: Int, token_count: Int) -> String:
        ...


alias MONTH_NAMES = InlineArray[String, 13](
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

alias MONTH_ABBREVIATIONS = InlineArray[String, 13](
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

alias DAY_NAMES = InlineArray[String, 8](
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
alias DAY_ABBREVIATIONS = InlineArray[String, 8]("", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
"""The day name abbreviations."""
alias formatter = _Formatter()
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

    fn format(self, m: Some[Formattable], fmt: String) -> String:
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

    fn replace(self, m: Some[Formattable], fmt: StringSlice) -> String:
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
                    result += m.replace_token(matched_byte, matched_count)
                    matched_byte = 0
                result += fmt[i]
                continue

            # If the current character is the same as the previous one, increment the count.
            if c == matched_byte:
                matched_count += 1
                continue

            # If the current character is different from the previous one, replace the previous tokens
            # and move onto the next token to track.
            result += m.replace_token(matched_byte, matched_count)
            matched_byte = c
            matched_count = 1

        # If no tokens were found, append an empty string and return the original.
        if matched_byte > 0:
            result += m.replace_token(matched_byte, matched_count)
        return result


alias _Y = ord("Y")
alias _M = ord("M")
alias _D = ord("D")
alias _d = ord("d")
alias _H = ord("H")
alias _h = ord("h")
alias _m = ord("m")
alias _s = ord("s")
alias _S = ord("S")
alias _X = ord("X")
alias _x = ord("x")
alias _Z = ord("Z")
alias _A = ord("A")
alias _a = ord("a")
