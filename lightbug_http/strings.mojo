from memory import Span
from lightbug_http.io.bytes import Bytes, bytes, byte

alias strSlash = "/"
alias strHttp = "http"
alias http = "http"
alias strHttps = "https"
alias https = "https"
alias strHttp11 = "HTTP/1.1"
alias strHttp10 = "HTTP/1.0"

alias strMethodGet = "GET"

alias rChar = "\r"
alias nChar = "\n"
alias lineBreak = rChar + nChar
alias colonChar = ":"

alias empty_string = ""
alias whitespace = " "
alias whitespace_byte = ord(whitespace)
alias tab = "\t"
alias tab_byte = ord(tab)


struct BytesConstant:
    alias whitespace = byte(whitespace)
    alias colon = byte(colonChar)
    alias rChar = byte(rChar)
    alias nChar = byte(nChar)

    alias CRLF = bytes(lineBreak)
    alias DOUBLE_CRLF = bytes(lineBreak + lineBreak)


fn to_string[T: Writable](value: T) -> String:
    return String.write(value)


fn to_string(b: Span[UInt8]) -> String:
    """Creates a String from a copy of the provided Span of bytes.

    Args:
        b: The Span of bytes to convert to a String.
    """
    return String(StringSlice(unsafe_from_utf8=b))


fn to_string(owned bytes: Bytes) -> String:
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
