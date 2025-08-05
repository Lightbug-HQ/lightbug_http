"""HTTP status codes and methods for Mojo. Straightforward translation from https://github.com/python/cpython/blob/main/Lib/http/__init__.py

Status codes from the following RFCs are all observed:
    * RFC 9110: HTTP Semantics, obsoletes 7231, which obsoleted 2616
    * RFC 6585: Additional HTTP Status Codes
    * RFC 3229: Delta encoding in HTTP
    * RFC 4918: HTTP Extensions for WebDAV, obsoletes 2518
    * RFC 5842: Binding Extensions to WebDAV
    * RFC 7238: Permanent Redirect
    * RFC 2295: Transparent Content Negotiation in HTTP
    * RFC 2774: An HTTP Extension Framework
    * RFC 7725: An HTTP Status Code to Report Legal Obstacles
    * RFC 7540: Hypertext Transfer Protocol Version 2 (HTTP/2)
    * RFC 2324: Hyper Text Coffee Pot Control Protocol (HTCPCP/1.0)
    * RFC 8297: An HTTP Status Code for Indicating Hints
    * RFC 8470: Using Early Data in HTTP
"""

struct HTTPStatus:
    var code: Int
    var phrase: String
    
    fn __init__(out self, code: Int, phrase: String):
        self.code = code
        self.phrase = phrase
    
    fn is_informational(self) -> Bool:
        return 100 <= self.code <= 199
    
    fn is_success(self) -> Bool:
        return 200 <= self.code <= 299
    
    fn is_redirection(self) -> Bool:
        return 300 <= self.code <= 399
    
    fn is_client_error(self) -> Bool:
        return 400 <= self.code <= 499
    
    fn is_server_error(self) -> Bool:
        return 500 <= self.code <= 599
    
    # Informational
    alias CONTINUE = HTTPStatus(100, "Continue")
    alias SWITCHING_PROTOCOLS = HTTPStatus(101, "Switching Protocols")
    alias PROCESSING = HTTPStatus(102, "Processing")
    alias EARLY_HINTS = HTTPStatus(103, "Early Hints")

    # Success
    alias OK = HTTPStatus(200, "OK")
    alias CREATED = HTTPStatus(201, "Created")
    alias ACCEPTED = HTTPStatus(202, "Accepted")
    alias NON_AUTHORITATIVE_INFORMATION = HTTPStatus(203, "Non-Authoritative Information")
    alias NO_CONTENT = HTTPStatus(204, "No Content")
    alias RESET_CONTENT = HTTPStatus(205, "Reset Content")
    alias PARTIAL_CONTENT = HTTPStatus(206, "Partial Content")
    alias MULTI_STATUS = HTTPStatus(207, "Multi-Status")
    alias ALREADY_REPORTED = HTTPStatus(208, "Already Reported")
    alias IM_USED = HTTPStatus(226, "IM Used")

    # Redirection
    alias MULTIPLE_CHOICES = HTTPStatus(300, "Multiple Choices")
    alias MOVED_PERMANENTLY = HTTPStatus(301, "Moved Permanently")
    alias FOUND = HTTPStatus(302, "Found")
    alias SEE_OTHER = HTTPStatus(303, "See Other")
    alias NOT_MODIFIED = HTTPStatus(304, "Not Modified")
    alias USE_PROXY = HTTPStatus(305, "Use Proxy")
    alias TEMPORARY_REDIRECT = HTTPStatus(307, "Temporary Redirect")
    alias PERMANENT_REDIRECT = HTTPStatus(308, "Permanent Redirect")

    # Client Error
    alias BAD_REQUEST = HTTPStatus(400, "Bad Request")
    alias UNAUTHORIZED = HTTPStatus(401, "Unauthorized")
    alias PAYMENT_REQUIRED = HTTPStatus(402, "Payment Required")
    alias FORBIDDEN = HTTPStatus(403, "Forbidden")
    alias NOT_FOUND = HTTPStatus(404, "Not Found")
    alias METHOD_NOT_ALLOWED = HTTPStatus(405, "Method Not Allowed")
    alias NOT_ACCEPTABLE = HTTPStatus(406, "Not Acceptable")
    alias PROXY_AUTHENTICATION_REQUIRED = HTTPStatus(407, "Proxy Authentication Required")
    alias REQUEST_TIMEOUT = HTTPStatus(408, "Request Timeout")
    alias CONFLICT = HTTPStatus(409, "Conflict")
    alias GONE = HTTPStatus(410, "Gone")
    alias LENGTH_REQUIRED = HTTPStatus(411, "Length Required")
    alias PRECONDITION_FAILED = HTTPStatus(412, "Precondition Failed")
    alias CONTENT_TOO_LARGE = HTTPStatus(413, "Content Too Large")
    alias REQUEST_ENTITY_TOO_LARGE = HTTPStatus(413, "Content Too Large")
    alias URI_TOO_LONG = HTTPStatus(414, "URI Too Long")
    alias REQUEST_URI_TOO_LONG = HTTPStatus(414, "URI Too Long")
    alias UNSUPPORTED_MEDIA_TYPE = HTTPStatus(415, "Unsupported Media Type")
    alias RANGE_NOT_SATISFIABLE = HTTPStatus(416, "Range Not Satisfiable")
    alias REQUESTED_RANGE_NOT_SATISFIABLE = HTTPStatus(416, "Range Not Satisfiable")
    alias EXPECTATION_FAILED = HTTPStatus(417, "Expectation Failed")
    alias IM_A_TEAPOT = HTTPStatus(418, "I'm a Teapot")
    alias MISDIRECTED_REQUEST = HTTPStatus(421, "Misdirected Request")
    alias UNPROCESSABLE_CONTENT = HTTPStatus(422, "Unprocessable Content")
    alias UNPROCESSABLE_ENTITY = HTTPStatus(422, "Unprocessable Content")
    alias LOCKED = HTTPStatus(423, "Locked")
    alias FAILED_DEPENDENCY = HTTPStatus(424, "Failed Dependency")
    alias TOO_EARLY = HTTPStatus(425, "Too Early")
    alias UPGRADE_REQUIRED = HTTPStatus(426, "Upgrade Required")
    alias PRECONDITION_REQUIRED = HTTPStatus(428, "Precondition Required")
    alias TOO_MANY_REQUESTS = HTTPStatus(429, "Too Many Requests")
    alias REQUEST_HEADER_FIELDS_TOO_LARGE = HTTPStatus(431, "Request Header Fields Too Large")
    alias UNAVAILABLE_FOR_LEGAL_REASONS = HTTPStatus(451, "Unavailable For Legal Reasons")

    # Server Errors
    alias INTERNAL_SERVER_ERROR = HTTPStatus(500, "Internal Server Error")
    alias NOT_IMPLEMENTED = HTTPStatus(501, "Not Implemented")
    alias BAD_GATEWAY = HTTPStatus(502, "Bad Gateway")
    alias SERVICE_UNAVAILABLE = HTTPStatus(503, "Service Unavailable")
    alias GATEWAY_TIMEOUT = HTTPStatus(504, "Gateway Timeout")
    alias HTTP_VERSION_NOT_SUPPORTED = HTTPStatus(505, "HTTP Version Not Supported")
    alias VARIANT_ALSO_NEGOTIATES = HTTPStatus(506, "Variant Also Negotiates")
    alias INSUFFICIENT_STORAGE = HTTPStatus(507, "Insufficient Storage")
    alias LOOP_DETECTED = HTTPStatus(508, "Loop Detected")
    alias NOT_EXTENDED = HTTPStatus(510, "Not Extended")
    alias NETWORK_AUTHENTICATION_REQUIRED = HTTPStatus(511, "Network Authentication Required")

struct HTTPMethod:
    var value: String
    
    fn __init__(out self, value: String):
        self.value = value

    alias CONNECT = HTTPMethod("CONNECT")
    alias DELETE = HTTPMethod("DELETE")
    alias GET = HTTPMethod("GET")
    alias HEAD = HTTPMethod("HEAD")
    alias OPTIONS = HTTPMethod("OPTIONS")
    alias PATCH = HTTPMethod("PATCH")
    alias POST = HTTPMethod("POST")
    alias PUT = HTTPMethod("PUT")
    alias TRACE = HTTPMethod("TRACE")