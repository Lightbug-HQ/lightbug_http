from lightbug_http.header import HeaderKey


struct Cookie(Copyable):
    comptime EXPIRES = "Expires"
    comptime MAX_AGE = "Max-Age"
    comptime DOMAIN = "Domain"
    comptime PATH = "Path"
    comptime SECURE = "Secure"
    comptime HTTP_ONLY = "HttpOnly"
    comptime SAME_SITE = "SameSite"
    comptime PARTITIONED = "Partitioned"

    comptime SEPERATOR = "; "
    comptime EQUAL = "="

    var name: String
    var value: String
    var expires: Expiration
    var secure: Bool
    var http_only: Bool
    var partitioned: Bool
    var same_site: Optional[SameSite]
    var domain: Optional[String]
    var path: Optional[String]
    var max_age: Optional[Duration]

    @staticmethod
    fn from_set_header(header_str: String) raises -> Self:
        var parts = header_str.split(Cookie.SEPERATOR)
        if len(parts) < 1:
            raise Error("invalid Cookie")

        var cookie = Cookie("", String(parts[0]), path=String("/"))
        if Cookie.EQUAL in parts[0]:
            var name_value = parts[0].split(Cookie.EQUAL)
            cookie.name = String(name_value[0])
            cookie.value = String(name_value[1])

        for i in range(1, len(parts)):
            var part = parts[i]
            if part == Cookie.PARTITIONED:
                cookie.partitioned = True
            elif part == Cookie.SECURE:
                cookie.secure = True
            elif part == Cookie.HTTP_ONLY:
                cookie.http_only = True
            elif part.startswith(Cookie.SAME_SITE):
                cookie.same_site = SameSite.from_string(String(part.removeprefix(Cookie.SAME_SITE + Cookie.EQUAL)))
            elif part.startswith(Cookie.DOMAIN):
                cookie.domain = String(part.removeprefix(Cookie.DOMAIN + Cookie.EQUAL))
            elif part.startswith(Cookie.PATH):
                cookie.path = String(part.removeprefix(Cookie.PATH + Cookie.EQUAL))
            elif part.startswith(Cookie.MAX_AGE):
                cookie.max_age = Duration.from_string(String(part.removeprefix(Cookie.MAX_AGE + Cookie.EQUAL)))
            elif part.startswith(Cookie.EXPIRES):
                var expires = Expiration.from_string(String(part.removeprefix(Cookie.EXPIRES + Cookie.EQUAL)))
                if expires:
                    cookie.expires = expires.value().copy()

        return cookie^

    fn __init__(
        out self,
        name: String,
        value: String,
        expires: Expiration = Expiration.session(),
        max_age: Optional[Duration] = Optional[Duration](None),
        domain: Optional[String] = Optional[String](None),
        path: Optional[String] = Optional[String](None),
        same_site: Optional[SameSite] = Optional[SameSite](None),
        secure: Bool = False,
        http_only: Bool = False,
        partitioned: Bool = False,
    ):
        self.name = name
        self.value = value
        self.expires = expires.copy()
        self.max_age = max_age
        self.domain = domain
        self.path = path
        self.secure = secure
        self.http_only = http_only
        self.same_site = same_site
        self.partitioned = partitioned

    fn __str__(self) -> String:
        return String.write("Name: ", self.name, " Value: ", self.value)

    fn __copyinit__(out self: Cookie, existing: Cookie):
        self.name = existing.name
        self.value = existing.value
        self.max_age = existing.max_age
        self.expires = existing.expires.copy()
        self.domain = existing.domain
        self.path = existing.path
        self.secure = existing.secure
        self.http_only = existing.http_only
        self.same_site = existing.same_site
        self.partitioned = existing.partitioned

    fn __moveinit__(out self: Cookie, deinit existing: Cookie):
        self.name = existing.name^
        self.value = existing.value^
        self.max_age = existing.max_age^
        self.expires = existing.expires^
        self.domain = existing.domain^
        self.path = existing.path^
        self.secure = existing.secure
        self.http_only = existing.http_only
        self.same_site = existing.same_site^
        self.partitioned = existing.partitioned

    fn clear_cookie(mut self):
        self.max_age = Optional[Duration](None)
        self.expires = Expiration.invalidate()

    fn to_header(self) raises -> Header:
        return Header(HeaderKey.SET_COOKIE, self.build_header_value())

    fn build_header_value(self) -> String:
        var header_value = String.write(self.name, Cookie.EQUAL, self.value)
        if self.expires.is_datetime():
            var v: Optional[String]
            try:
                v = self.expires.http_date_timestamp()
            except:
                v = None
                # TODO: This should be a hardfail however Writeable trait write_to method does not raise
                # the call flow needs to be refactored
                pass

            if v:
                header_value.write(Cookie.SEPERATOR, Cookie.EXPIRES, Cookie.EQUAL, v.value())
        if self.max_age:
            header_value.write(
                Cookie.SEPERATOR, Cookie.MAX_AGE, Cookie.EQUAL, String(self.max_age.value().total_seconds)
            )
        if self.domain:
            header_value.write(Cookie.SEPERATOR, Cookie.DOMAIN, Cookie.EQUAL, self.domain.value())
        if self.path:
            header_value.write(Cookie.SEPERATOR, Cookie.PATH, Cookie.EQUAL, self.path.value())
        if self.secure:
            header_value.write(Cookie.SEPERATOR, Cookie.SECURE)
        if self.http_only:
            header_value.write(Cookie.SEPERATOR, Cookie.HTTP_ONLY)
        if self.same_site:
            header_value.write(Cookie.SEPERATOR, Cookie.SAME_SITE, Cookie.EQUAL, String(self.same_site.value()))
        if self.partitioned:
            header_value.write(Cookie.SEPERATOR, Cookie.PARTITIONED)
        return header_value
