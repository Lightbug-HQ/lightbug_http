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
    """Check if a byte is within US-ASCII range (0x00-0x7F).
    
    Args:
        b: The byte to check.
        
    Returns:
        True if the byte is US-ASCII compliant.
    """
    return b <= US_ASCII_MAX


fn is_iso_8859_1_octet(b: UInt8) -> Bool:
    """Check if a byte is within ISO-8859-1 range (0x00-0xFF).
    
    Args:
        b: The byte to check.
        
    Returns:
        True if the byte is ISO-8859-1 compliant.
    """
    return b <= ISO_8859_1_MAX


fn validate_http_message_octets[origin: Origin](data: Span[UInt8, origin]) raises -> Span[UInt8, origin]:
    """RFC 9112 Section 2.2-2: Validate HTTP message as sequence of octets.
    
    A recipient MUST parse an HTTP message as a sequence of octets in an encoding 
    that is a superset of US-ASCII. This function validates that the message can
    be safely parsed as octets and detects invalid multibyte UTF-8 sequences.
    
    Args:
        data: The raw bytes of the HTTP message.
        
    Returns:
        The validated span of bytes safe for parsing.
        
    Raises:
        Error: If the data contains invalid multi-byte sequences that could
               create security vulnerabilities (like embedded LF in UTF-8).
    """
    for i in range(len(data)):
        var b = data[i]
        
        # Allow all ISO-8859-1 bytes (0x00-0xFF)
        if is_iso_8859_1_octet(b):
            # Check for potential UTF-8 multibyte sequence vulnerabilities
            if b >= 0x80:  # Non-ASCII byte
                # Check if this looks like a UTF-8 start byte
                if b >= 0xC0 and b <= 0xF7:  # UTF-8 start bytes
                    # This could be start of multibyte sequence - check for embedded LF
                    if i + 1 < len(data) and data[i + 1] == 0x0A:  # LF embedded in sequence
                        raise Error(
                            "RFC 9112 violation: LF (0x0A) embedded in potential multibyte sequence at position " + 
                            String(i + 1) + ". This creates security vulnerabilities."
                        )
                elif b >= 0x80 and b <= 0xBF:  # UTF-8 continuation byte without proper start
                    # Check if previous byte is valid UTF-8 start, if not this is invalid
                    if i == 0 or (data[i - 1] < 0xC0):  # No proper UTF-8 start byte before
                        # Check if this continuation byte contains control characters
                        if i + 1 < len(data) and data[i + 1] == 0x0A:  # LF after invalid continuation
                            raise Error(
                                "RFC 9112 violation: LF (0x0A) after invalid UTF-8 continuation byte at position " + 
                                String(i + 1) + ". This creates security vulnerabilities."
                            )
            continue
            
        # This should never happen since is_iso_8859_1_octet covers 0x00-0xFF
        raise Error(
            "RFC 9112 violation: Invalid octet 0x" + hex(Int(b)) + 
            " at position " + String(i) + 
            ". HTTP messages must use encoding superset of US-ASCII."
        )
    
    return data


fn safe_to_string_rfc9112[origin: Origin](b: Span[UInt8, origin]) raises -> String:
    """RFC 9112 compliant conversion of octets to String.
    
    Creates a String from octets using ISO-8859-1 encoding (superset of US-ASCII).
    This avoids security vulnerabilities from treating multi-byte UTF-8 sequences
    as individual characters.
    
    Args:
        b: The validated span of bytes (must pass validate_http_message_octets).
        
    Returns:
        A String created from the octets using safe encoding.
        
    Raises:
        Error: If the bytes contain invalid sequences for HTTP parsing.
    """
    var validated_span = validate_http_message_octets(b)
    
    return String(StringSlice(unsafe_from_utf8=validated_span))


fn percent_encode_invalid_octets[origin: Origin](data: Span[UInt8, origin]) -> String:
    """Percent-encode octets that are not safe for HTTP message parsing.
    
    This is a fallback approach when we encounter bytes that cannot be safely
    interpreted as US-ASCII superset encoding.
    
    Args:
        data: The raw bytes that may contain unsafe sequences.
        
    Returns:
        A String with unsafe octets percent-encoded.
    """
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


fn to_string[T: Writable](value: T) -> String:
    return String.write(value)


fn to_string(b: Span[UInt8]) -> String:
    """Creates a String from a copy of the provided Span of bytes.

    Args:
        b: The Span of bytes to convert to a String.
    """
    return String(StringSlice(unsafe_from_utf8=b))


fn to_string_rfc9112_safe[origin: Origin](b: Span[UInt8, origin]) -> String:
    """RFC 9112 compliant String creation with fallback to percent-encoding.
    
    Attempts to create a String using safe octet parsing. If that fails,
    falls back to percent-encoding unsafe sequences.
    
    Args:
        b: The Span of bytes to convert to a String.
        
    Returns:
        A String created safely according to RFC 9112.
    """
    try:
        return safe_to_string_rfc9112(b)
    except:
        # Fallback to percent-encoding for unsafe sequences
        return percent_encode_invalid_octets(b)


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
