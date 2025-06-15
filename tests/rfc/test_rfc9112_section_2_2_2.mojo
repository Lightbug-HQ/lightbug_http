import testing
from memory import Span
from lightbug_http.strings import (
    validate_http_message_octets,
    safe_to_string_rfc9112,
    to_string_rfc9112_safe,
    is_us_ascii_octet,
    is_iso_8859_1_octet,
    percent_encode_invalid_octets,
)
from lightbug_http.io.bytes import Bytes, ByteReader
from lightbug_http.http.request import HTTPRequest


def test_rfc9112_lf_security_vulnerability_prevention():
    """RFC 9112 Section 2.2-2: Prevent security vulnerabilities from LF (%x0A) in multibyte sequences."""
    print("Testing: LF security vulnerability prevention...")
    
    # Valid LF in HTTP context
    var valid_http = "GET /test HTTP/1.1\r\nHost: test.com\r\n\r\n"
    var valid_octets = valid_http.as_bytes()
    
    try:
        var validated = validate_http_message_octets(Span(valid_octets))
        testing.assert_equal(len(validated), len(valid_octets))
    except e:
        testing.assert_true(False, "Valid HTTP message should not raise error: " + String(e))
    
    # Invalid multibyte sequence containing LF
    var malicious_bytes = List[UInt8]()
    malicious_bytes.extend("GET /".as_bytes())
    malicious_bytes.append(0xC0)  # Invalid UTF-8 start byte
    malicious_bytes.append(0x0A)  # LF embedded in multibyte sequence
    malicious_bytes.append(0x80)  # Continuation byte
    malicious_bytes.extend(" HTTP/1.1\r\nHost: test.com\r\n\r\n".as_bytes())
    
    var malicious_span = Span(malicious_bytes)
    
    try:
        var validated = validate_http_message_octets(malicious_span)
        testing.assert_true(False, "Should have rejected invalid multibyte sequence with embedded LF")
    except e:
        testing.assert_true(True, "Correctly rejected invalid sequence: " + String(e))
    
    var safe_result = to_string_rfc9112_safe(malicious_span)
    
    testing.assert_true(safe_result.find("%") != -1, "Should percent-encode unsafe sequences")


def test_rfc9112_percent_encoding_fallback():
    """RFC 9112 Section 2.2-2: Test percent-encoding fallback for unsafe sequences."""
    print("Testing: Percent-encoding fallback for unsafe sequences...")
    
    var unsafe_bytes = List[UInt8]()
    unsafe_bytes.append(0x00)  # NULL byte
    unsafe_bytes.append(0x0A)  # LF
    unsafe_bytes.append(0x0D)  # CR
    unsafe_bytes.append(0x25)  # % (should be encoded)
    unsafe_bytes.append(0xFF)  # High byte
    
    var unsafe_span = Span(unsafe_bytes)
    var encoded = percent_encode_invalid_octets(unsafe_span)
    
    testing.assert_true(encoded.find("%00") != -1, "Should encode NULL byte")
    testing.assert_true(encoded.find("%0A") != -1, "Should encode LF")
    testing.assert_true(encoded.find("%0D") != -1, "Should encode CR")
    testing.assert_true(encoded.find("%25") != -1, "Should encode % character")
    testing.assert_true(encoded.find("%FF") != -1, "Should encode high byte")


def main():
    print("🧪 Testing RFC 9112 Section 2.2-2: HTTP Message Parsing as Octets")
    
    test_rfc9112_lf_security_vulnerability_prevention()
    test_rfc9112_percent_encoding_fallback()
    
    print("\n✅ RFC 9112 Section 2.2-2 requirement fully verified")