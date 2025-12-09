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
    comptime CRLF = Bytes("\r\n".as_bytes())
    comptime DOUBLE_CRLF = Bytes("\r\n\r\n".as_bytes())
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
