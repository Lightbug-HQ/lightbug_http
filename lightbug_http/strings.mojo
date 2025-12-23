from lightbug_http.io.bytes import Bytes, byte


comptime http = "http"
comptime https = "https"
comptime strHttp11 = "HTTP/1.1"
comptime strHttp10 = "HTTP/1.0"

comptime CR = "\r"
comptime LF = "\n"
comptime lineBreak = "\r\n"
comptime colonChar = ":"

comptime whitespace = " "


struct BytesConstant:
    comptime whitespace = byte[whitespace]()
    comptime colon = byte[colonChar]()
    comptime CR = byte[CR]()
    comptime LF = byte[LF]()
    comptime CRLF = "\r\n".as_bytes()
    comptime DOUBLE_CRLF = "\r\n\r\n".as_bytes()
    comptime TAB = byte["\t"]()
    comptime COLON = byte[":"]()
    comptime SEMICOLON = byte[";"]()

    comptime ZERO = byte["0"]()
    comptime ONE = byte["1"]()
    comptime NINE = byte["9"]()
    comptime A_UPPER = byte["A"]()
    comptime Z_UPPER = byte["Z"]()
    comptime A_LOWER = byte["a"]()
    comptime Z_LOWER = byte["z"]()
    comptime F_UPPER = byte["F"]()
    comptime F_LOWER = byte["f"]()
    comptime H = byte["H"]()
    comptime T = byte["T"]()
    comptime P = byte["P"]()
    comptime SLASH = byte["/"]()
    comptime EXCLAMATION = byte["!"]()
    comptime POUND = byte["#"]()
    comptime DOLLAR = byte["$"]()
    comptime PERCENT = byte["%"]()
    comptime AMPERSAND = byte["&"]()
    comptime APOSTROPHE = byte["'"]()
    comptime ASTERISK = byte["*"]()
    comptime PLUS = byte["+"]()
    comptime HYPHEN = byte["-"]()
    comptime DOT = byte["."]()
    comptime CARET = byte["^"]()
    comptime UNDERSCORE = byte["_"]()
    comptime BACKTICK = byte["`"]()
    comptime PIPE = byte["|"]()
    comptime TILDE = byte["~"]()



# Constants
comptime IS_PRINTABLE_ASCII_MASK = 0o137

fn is_printable_ascii(c: UInt8) -> Bool:
    return (c - 0x20) < IS_PRINTABLE_ASCII_MASK

# Token character map - represents which characters are valid in tokens
# According to RFC 7230: token = 1*tchar
# tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
#         "0"-"9" / "A"-"Z" / "^" / "_" / "`" / "a"-"z" / "|" / "~"
@always_inline
fn is_token_char(c: UInt8) -> Bool:
    """Check if character is a valid token character.

    Optimized to be inlined and extremely fast - compiles to simple range checks.
    """
    # Alphanumeric ranges
    if c >= BytesConstant.ZERO and c <= BytesConstant.NINE:  # 0-9
        return True
    if c >= BytesConstant.A_UPPER and c <= BytesConstant.Z_UPPER:  # A-Z
        return True
    if c >= BytesConstant.A_LOWER and c <= BytesConstant.Z_LOWER:  # a-z
        return True

    # Special characters allowed in tokens (ordered by ASCII value for branch prediction)
    # !  #  $  %  &  '  *  +  -  .  ^  _  `  |  ~
    return (
        c == BytesConstant.EXCLAMATION
        or c == BytesConstant.POUND
        or c == BytesConstant.DOLLAR
        or c == BytesConstant.PERCENT
        or c == BytesConstant.AMPERSAND
        or c == BytesConstant.APOSTROPHE
        or c == BytesConstant.ASTERISK
        or c == BytesConstant.PLUS
        or c == BytesConstant.HYPHEN
        or c == BytesConstant.DOT
        or c == BytesConstant.CARET
        or c == BytesConstant.UNDERSCORE
        or c == BytesConstant.BACKTICK
        or c == BytesConstant.PIPE
        or c == BytesConstant.TILDE
    )
