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


alias US_ASCII_MAX = 0x7F
alias ISO_8859_1_MAX = 0xFF


fn is_us_ascii_octet(b: UInt8) -> Bool:
    return b <= US_ASCII_MAX


fn is_iso_8859_1_octet(b: UInt8) -> Bool:
    return b <= ISO_8859_1_MAX


fn to_string[T: Writable](value: T) -> String:
    return String.write(value)


fn to_string(b: Span[UInt8]) -> String:
    """Creates a String from a copy of the provided Span of bytes.

    Args:
        b: The Span of bytes to convert to a String.
    """
    return String(StringSlice(unsafe_from_utf8=b))


fn to_string_rfc9112_safe[origin: Origin](b: Span[UInt8, origin]) -> String:
    try:
        var validated_span = validate_message_octets_iso_8859_1(b)
        return String(StringSlice(unsafe_from_utf8=validated_span))
    except:
        return percent_encode_octets(b)


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


fn percent_encode_octets[origin: Origin](data: Span[UInt8, origin]) -> String:
    var result = String()
    
    for i in range(len(data)):
        var b = data[i]
        
        if is_us_ascii_octet(b) and b >= 0x20 and b != 0x25:  # Printable ASCII except %
            result += chr(Int(b))
        else:
            # Fix hex formatting: ensure proper zero-padding
            var hex_val = hex(Int(b)).upper()
            # Remove "0X" prefix if present
            if hex_val.startswith("0X"):
                hex_val = hex_val[2:]
            # Ensure two-digit hex format
            if len(hex_val) == 1:
                result += "%0" + hex_val
            else:
                result += "%" + hex_val
    
    return result

fn validate_message_octets_iso_8859_1[origin: Origin](data: Span[UInt8, origin]) raises -> Span[UInt8, origin]:
    for i in range(len(data)):
        var b = data[i]
        
        if is_iso_8859_1_octet(b):
            if b >= 0x80:
                if b >= 0xC0 and b <= 0xF7:
                    if i + 1 < len(data) and data[i + 1] == 0x0A:
                        raise Error(
                            "."
                        )
                elif b >= 0x80 and b <= 0xBF:
                    if i == 0 or (data[i - 1] < 0xC0):
                        if i + 1 < len(data) and data[i + 1] == 0x0A:
                            raise Error(
                                "."
                            )
            continue
            
        # This should never happen since is_iso_8859_1_octet covers 0x00-0xFF
        raise Error(
            "Invalid octet 0x" + hex(Int(b)) + 
            " at position " + String(i) + 
            ". HTTP messages must use encoding superset of US-ASCII."
        )
    
    return data