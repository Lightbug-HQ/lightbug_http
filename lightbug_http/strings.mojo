from lightbug_http.io.bytes import Bytes, byte


comptime http = "http"
comptime https = "https"
comptime strHttp11 = "HTTP/1.1"
comptime strHttp10 = "HTTP/1.0"

comptime rChar = "\r"
comptime nChar = "\n"
comptime lineBreak = "\r\n"
comptime colonChar = ":"

comptime whitespace = " "


struct BytesConstant:
    comptime whitespace = byte[whitespace]()
    comptime colon = byte[colonChar]()
    comptime rChar = byte[rChar]()
    comptime nChar = byte[nChar]()

    comptime CRLF = Bytes("\r\n".as_bytes())
    comptime DOUBLE_CRLF = Bytes("\r\n\r\n".as_bytes())
