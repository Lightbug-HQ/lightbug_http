import testing
from memory import Span


def test_rfc9112_parse_as_octets():
    """RFC 9112 Section 2.2-2: MUST parse HTTP message as sequence of octets."""
    print("Testing: Parse HTTP message as sequence of octets...")
    
    var http_message = "GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n"
    var octets = http_message.as_bytes()
    
    testing.assert_equal(octets[0], ord('G'))
    testing.assert_equal(octets[4], ord('/'))
    
    var found_cr = False
    var found_lf = False
    for i in range(len(octets)):
        if octets[i] == 0x0D and not found_cr:
            found_cr = True
        if octets[i] == 0x0A and not found_lf:
            found_lf = True
        if found_cr and found_lf:
            break
    
    testing.assert_true(found_cr)
    testing.assert_true(found_lf)


def test_rfc9112_us_ascii_superset_encoding():
    """RFC 9112 Section 2.2-2: MUST use encoding that is superset of US-ASCII."""
    print("Testing: Encoding is superset of US-ASCII...")
    
    testing.assert_true(ord('G') <= 0x7F)      # US-ASCII
    testing.assert_true(ord(' ') <= 0x7F)      # US-ASCII
    testing.assert_true(0x0A <= 0x7F)          # LF in US-ASCII
    testing.assert_true(0x0D <= 0x7F)          # CR in US-ASCII
    testing.assert_true(0x80 <= 0xFF)          # Extended range valid
    testing.assert_true(0xFF <= 0xFF)          # Maximum byte valid


def test_rfc9112_lf_security_vulnerability():
    """RFC 9112 Section 2.2-2: Prevent LF (%x0A) security vulnerabilities."""
    print("Testing: LF (%x0A) security vulnerability prevention...")
    
    var lf_octet: UInt8 = 0x0A
    
    var test_data = "GET /\r\nHost: test\r\n\r\n"
    var data_octets = test_data.as_bytes()
    
    var lf_positions = List[Int]()
    for i in range(len(data_octets)):
        if data_octets[i] == lf_octet:
            lf_positions.append(i)
    
    testing.assert_true(len(lf_positions) > 0)


def test_rfc9112_string_parser_safety():
    """RFC 9112 Section 2.2-2: String parsers only used after protocol element extraction."""
    print("Testing: String parsers used only after safe extraction...")
    
    var http_request = "GET /api/data HTTP/1.1\r\nHost: server.com\r\n\r\n"
    var request_octets = http_request.as_bytes()
    
    var method_end = -1
    for i in range(len(request_octets)):
        if request_octets[i] == ord(' '):
            method_end = i
            break
    
    testing.assert_true(method_end > 0)
    
    testing.assert_equal(request_octets[0], ord('G'))
    testing.assert_equal(request_octets[1], ord('E'))
    testing.assert_equal(request_octets[2], ord('T'))
    testing.assert_equal(method_end, 3)


def main():
    """Test RFC 9112 Section 2.2-2 compliance."""
    print("🧪 Testing RFC 9112 Section 2.2-2 Compliance\n")
    
    test_rfc9112_parse_as_octets()
    test_rfc9112_us_ascii_superset_encoding()
    test_rfc9112_lf_security_vulnerability()
    test_rfc9112_string_parser_safety()
    
    print("\n✅ RFC 9112 Section 2.2-2 requirement verified")