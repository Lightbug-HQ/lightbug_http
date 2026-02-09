"""HTTP date formatting utilities (RFC 7231 Section 7.1.1.1)."""

from small_time.small_time import SmallTime, now


fn format_http_date(time: SmallTime) raises -> String:
    """Format a SmallTime as an HTTP date (IMF-fixdate format).

    Format: Day, DD Mon YYYY HH:MM:SS GMT
    Example: Wed, 21 Oct 2015 07:28:00 GMT

    Args:
        time: The time to format (should be in UTC).

    Returns:
        HTTP-formatted date string.
    """
    # Day names (0=Sunday, 1=Monday, ..., 6=Saturday)
    var day_names = List[String]()
    day_names.append("Sun")
    day_names.append("Mon")
    day_names.append("Tue")
    day_names.append("Wed")
    day_names.append("Thu")
    day_names.append("Fri")
    day_names.append("Sat")

    # Month names (1=January, ..., 12=December)
    var month_names = List[String]()
    month_names.append("Jan")
    month_names.append("Feb")
    month_names.append("Mar")
    month_names.append("Apr")
    month_names.append("May")
    month_names.append("Jun")
    month_names.append("Jul")
    month_names.append("Aug")
    month_names.append("Sep")
    month_names.append("Oct")
    month_names.append("Nov")
    month_names.append("Dec")

    var year = time.year
    var month = time.month
    var day = time.day
    var hour = time.hour
    var minute = time.minute
    var second = time.second

    # Calculate day of week (Zeller's congruence for Gregorian calendar)
    var q = day
    var m = month
    var y = year

    # Adjust for Zeller's formula (March = 3, ..., February = 14)
    if m < 3:
        m += 12
        y -= 1

    var k = y % 100  # Year of century
    var j = y // 100  # Zero-based century

    var h = (UInt(q) + ((13 * (UInt(m) + 1)) // 5) + k + (k // 4) + (j // 4) - (2 * j)) % 7

    # Convert to 0=Sunday format
    var day_of_week = (h + 6) % 7

    # Format: "Day, DD Mon YYYY HH:MM:SS GMT"
    # Format day, hour, minute, second with zero-padding
    var day_str = String(day)
    if day < 10:
        day_str = "0" + day_str
    var hour_str = String(hour)
    if hour < 10:
        hour_str = "0" + hour_str
    var minute_str = String(minute)
    if minute < 10:
        minute_str = "0" + minute_str
    var second_str = String(second)
    if second < 10:
        second_str = "0" + second_str

    return String(
        day_names[day_of_week],
        ", ",
        day_str,
        " ",
        month_names[month - 1],
        " ",
        String(year),
        " ",
        hour_str,
        ":",
        minute_str,
        ":",
        second_str,
        " GMT",
    )


fn http_date_now() -> String:
    """Get current time formatted as HTTP date.

    Returns:
        Current time in HTTP date format (IMF-fixdate).
    """
    try:
        return format_http_date(now(utc=True))
    except:
        # Fallback if time formatting fails
        return "Thu, 01 Jan 1970 00:00:00 GMT"
