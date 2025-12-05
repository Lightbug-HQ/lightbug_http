from lightbug_http.io.bytes import Bytes, byte, bytes


comptime strSlash = "/"
comptime strHttp = "http"
comptime http = "http"
comptime strHttps = "https"
comptime https = "https"
comptime strHttp11 = "HTTP/1.1"
comptime strHttp10 = "HTTP/1.0"

comptime strMethodGet = "GET"

comptime rChar = "\r"
comptime nChar = "\n"
comptime lineBreak = rChar + nChar
comptime colonChar = ":"

comptime empty_string = ""
comptime whitespace = " "
comptime whitespace_byte = ord(whitespace)
comptime tab = "\t"
comptime tab_byte = ord(tab)


struct BytesConstant:
    comptime whitespace = byte(whitespace)
    comptime colon = byte(colonChar)
    comptime rChar = byte(rChar)
    comptime nChar = byte(nChar)

    comptime CRLF = bytes(lineBreak)
    comptime DOUBLE_CRLF = bytes(lineBreak + lineBreak)


fn to_string[T: Writable](value: T) -> String:
    return String.write(value)


fn to_string(b: Span[UInt8]) -> String:
    """Creates a String from a copy of the provided Span of bytes.

    Args:
        b: The Span of bytes to convert to a String.
    """
    return String(StringSlice(unsafe_from_utf8=b))


fn to_string(var bytes: Bytes) -> String:
    """Creates a String from the provided List of bytes.
    If you do not transfer ownership of the List, the List will be copied.

    Args:
        bytes: The List of bytes to convert to a String.
    """
    var result = String()
    result.write_bytes(bytes)
    return result^


fn find_all(s: String, sub_str: String) -> List[Int]:
    match_idxs = List[Int]()
    var current_idx: Int = s.find(sub_str)
    while current_idx > -1:
        match_idxs.append(current_idx)
        current_idx = s.find(sub_str, start=current_idx + 1)
    return match_idxs^
