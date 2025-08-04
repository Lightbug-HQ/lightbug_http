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
    var description: String
    
    fn __init__(out self, code: Int, phrase: String, description: String = ""):
        self.code = code
        self.phrase = phrase
        self.description = description
    
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
    alias CONTINUE = HTTPStatus(100, "Continue", "Request received, please continue")
    alias SWITCHING_PROTOCOLS = HTTPStatus(101, "Switching Protocols", "Switching to new protocol; obey Upgrade header")
    alias PROCESSING = HTTPStatus(102, "Processing", "Server is processing the request")
    alias EARLY_HINTS = HTTPStatus(103, "Early Hints", "Headers sent to prepare for the response")

    # Success
    alias OK = HTTPStatus(200, "OK", "Request fulfilled, document follows")
    alias CREATED = HTTPStatus(201, "Created", "Document created, URL follows")
    alias ACCEPTED = HTTPStatus(202, "Accepted", "Request accepted, processing continues off-line")
    alias NON_AUTHORITATIVE_INFORMATION = HTTPStatus(203, "Non-Authoritative Information", "Request fulfilled from cache")
    alias NO_CONTENT = HTTPStatus(204, "No Content", "Request fulfilled, nothing follows")
    alias RESET_CONTENT = HTTPStatus(205, "Reset Content", "Clear input form for further input")
    alias PARTIAL_CONTENT = HTTPStatus(206, "Partial Content", "Partial content follows")
    alias MULTI_STATUS = HTTPStatus(207, "Multi-Status", "Response contains multiple statuses in the body")
    alias ALREADY_REPORTED = HTTPStatus(208, "Already Reported", "Operation has already been reported")
    alias IM_USED = HTTPStatus(226, "IM Used", "Request completed using instance manipulations")

    # Redirection
    alias MULTIPLE_CHOICES = HTTPStatus(300, "Multiple Choices", "Object has several resources -- see URI list")
    alias MOVED_PERMANENTLY = HTTPStatus(301, "Moved Permanently", "Object moved permanently -- see URI list")
    alias FOUND = HTTPStatus(302, "Found", "Object moved temporarily -- see URI list")
    alias SEE_OTHER = HTTPStatus(303, "See Other", "Object moved -- see Method and URL list")
    alias NOT_MODIFIED = HTTPStatus(304, "Not Modified", "Document has not changed since given time")
    alias USE_PROXY = HTTPStatus(305, "Use Proxy", "You must use proxy specified in Location to access this resource")
    alias TEMPORARY_REDIRECT = HTTPStatus(307, "Temporary Redirect", "Object moved temporarily -- see URI list")
    alias PERMANENT_REDIRECT = HTTPStatus(308, "Permanent Redirect", "Object moved permanently -- see URI list")

    # Client Error
    alias BAD_REQUEST = HTTPStatus(400, "Bad Request", "Bad request syntax or unsupported method")
    alias UNAUTHORIZED = HTTPStatus(401, "Unauthorized", "No permission -- see authorization schemes")
    alias PAYMENT_REQUIRED = HTTPStatus(402, "Payment Required", "No payment -- see charging schemes")
    alias FORBIDDEN = HTTPStatus(403, "Forbidden", "Request forbidden -- authorization will not help")
    alias NOT_FOUND = HTTPStatus(404, "Not Found", "Nothing matches the given URI")
    alias METHOD_NOT_ALLOWED = HTTPStatus(405, "Method Not Allowed", "Specified method is invalid for this resource")
    alias NOT_ACCEPTABLE = HTTPStatus(406, "Not Acceptable", "URI not available in preferred format")
    alias PROXY_AUTHENTICATION_REQUIRED = HTTPStatus(407, "Proxy Authentication Required", "You must authenticate with this proxy before proceeding")
    alias REQUEST_TIMEOUT = HTTPStatus(408, "Request Timeout", "Request timed out; try again later")
    alias CONFLICT = HTTPStatus(409, "Conflict", "Request conflict")
    alias GONE = HTTPStatus(410, "Gone", "URI no longer exists and has been permanently removed")
    alias LENGTH_REQUIRED = HTTPStatus(411, "Length Required", "Client must specify Content-Length")
    alias PRECONDITION_FAILED = HTTPStatus(412, "Precondition Failed", "Precondition in headers is false")
    alias CONTENT_TOO_LARGE = HTTPStatus(413, "Content Too Large", "Content is too large")
    alias REQUEST_ENTITY_TOO_LARGE = HTTPStatus(413, "Content Too Large", "Content is too large")
    alias URI_TOO_LONG = HTTPStatus(414, "URI Too Long", "URI is too long")
    alias REQUEST_URI_TOO_LONG = HTTPStatus(414, "URI Too Long", "URI is too long")
    alias UNSUPPORTED_MEDIA_TYPE = HTTPStatus(415, "Unsupported Media Type", "Entity body in unsupported format")
    alias RANGE_NOT_SATISFIABLE = HTTPStatus(416, "Range Not Satisfiable", "Cannot satisfy request range")
    alias REQUESTED_RANGE_NOT_SATISFIABLE = HTTPStatus(416, "Range Not Satisfiable", "Cannot satisfy request range")
    alias EXPECTATION_FAILED = HTTPStatus(417, "Expectation Failed", "Expect condition could not be satisfied")
    alias IM_A_TEAPOT = HTTPStatus(418, "I'm a Teapot", "Server refuses to brew coffee because it is a teapot")
    alias MISDIRECTED_REQUEST = HTTPStatus(421, "Misdirected Request", "Server is not able to produce a response")
    alias UNPROCESSABLE_CONTENT = HTTPStatus(422, "Unprocessable Content", "Server is not able to process the contained instructions")
    alias UNPROCESSABLE_ENTITY = HTTPStatus(422, "Unprocessable Content", "Server is not able to process the contained instructions")
    alias LOCKED = HTTPStatus(423, "Locked", "Resource of a method is locked")
    alias FAILED_DEPENDENCY = HTTPStatus(424, "Failed Dependency", "Dependent action of the request failed")
    alias TOO_EARLY = HTTPStatus(425, "Too Early", "Server refuses to process a request that might be replayed")
    alias UPGRADE_REQUIRED = HTTPStatus(426, "Upgrade Required", "Server refuses to perform the request using the current protocol")
    alias PRECONDITION_REQUIRED = HTTPStatus(428, "Precondition Required", "The origin server requires the request to be conditional")
    alias TOO_MANY_REQUESTS = HTTPStatus(429, "Too Many Requests", "The user has sent too many requests in a given amount of time (\"rate limiting\")")
    alias REQUEST_HEADER_FIELDS_TOO_LARGE = HTTPStatus(431, "Request Header Fields Too Large", "The server is unwilling to process the request because its header fields are too large")
    alias UNAVAILABLE_FOR_LEGAL_REASONS = HTTPStatus(451, "Unavailable For Legal Reasons", "The server is denying access to the resource as a consequence of a legal demand")

    # Server Errors
    alias INTERNAL_SERVER_ERROR = HTTPStatus(500, "Internal Server Error", "Server got itself in trouble")
    alias NOT_IMPLEMENTED = HTTPStatus(501, "Not Implemented", "Server does not support this operation")
    alias BAD_GATEWAY = HTTPStatus(502, "Bad Gateway", "Invalid responses from another server/proxy")
    alias SERVICE_UNAVAILABLE = HTTPStatus(503, "Service Unavailable", "The server cannot process the request due to a high load")
    alias GATEWAY_TIMEOUT = HTTPStatus(504, "Gateway Timeout", "The gateway server did not receive a timely response")
    alias HTTP_VERSION_NOT_SUPPORTED = HTTPStatus(505, "HTTP Version Not Supported", "Cannot fulfill request")
    alias VARIANT_ALSO_NEGOTIATES = HTTPStatus(506, "Variant Also Negotiates", "Server has an internal configuration error")
    alias INSUFFICIENT_STORAGE = HTTPStatus(507, "Insufficient Storage", "Server is not able to store the representation")
    alias LOOP_DETECTED = HTTPStatus(508, "Loop Detected", "Server encountered an infinite loop while processing a request")
    alias NOT_EXTENDED = HTTPStatus(510, "Not Extended", "Request does not meet the resource access policy")
    alias NETWORK_AUTHENTICATION_REQUIRED = HTTPStatus(511, "Network Authentication Required", "The client needs to authenticate to gain network access")

struct HTTPMethod:
    var value: String
    var description: String
    
    fn __init__(out self, value: String, description: String):
        self.value = value
        self.description = description

    alias CONNECT = HTTPMethod("CONNECT", "Establish a connection to the server.")
    alias DELETE = HTTPMethod("DELETE", "Remove the target.")
    alias GET = HTTPMethod("GET", "Retrieve the target.")
    alias HEAD = HTTPMethod("HEAD", "Same as GET, but only retrieve the status line and header section.")
    alias OPTIONS = HTTPMethod("OPTIONS", "Describe the communication options for the target.")
    alias PATCH = HTTPMethod("PATCH", "Apply partial modifications to a target.")
    alias POST = HTTPMethod("POST", "Perform target-specific processing with the request payload.")
    alias PUT = HTTPMethod("PUT", "Replace the target with the request payload.")
    alias TRACE = HTTPMethod("TRACE", "Perform a message loop-back test along the path to the target.")