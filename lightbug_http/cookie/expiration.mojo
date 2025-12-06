from collections import Optional

from small_time.small_time import SmallTime, parse_time_with_format


comptime HTTP_DATE_FORMAT = "ddd, DD MMM YYYY HH:mm:ss ZZZ"


@fieldwise_init
struct Expiration(Copyable):
    var variant: UInt8
    var datetime: Optional[SmallTime]

    @staticmethod
    fn session() -> Self:
        return Self(variant=0, datetime=None)

    @staticmethod
    fn from_datetime(var time: SmallTime) -> Self:
        return Self(variant=1, datetime=time^)

    @staticmethod
    fn from_string(str: String) -> Optional[Expiration]:
        try:
            return Self.from_datetime(parse_time_with_format(str, HTTP_DATE_FORMAT, TimeZone.GMT))
        except:
            return None

    @staticmethod
    fn invalidate() -> Self:
        return Self(variant=1, datetime=SmallTime(1970, 1, 1, 0, 0, 0, 0))

    fn is_session(self) -> Bool:
        return self.variant == 0

    fn is_datetime(self) -> Bool:
        return self.variant == 1

    fn http_date_timestamp(self) raises -> Optional[String]:
        if not self.datetime:
            return Optional[String](None)

        # TODO fix this it breaks time and space (replacing timezone might add or remove something sometimes)
        var dt = self.datetime.value().copy()
        dt.time_zone = TimeZone.GMT
        return Optional[String](dt.format[HTTP_DATE_FORMAT]())

    fn __eq__(self, other: Self) -> Bool:
        if self.variant != other.variant:
            return False
        if self.variant == 1:
            if Bool(self.datetime) != Bool(other.datetime):
                return False
            elif not Bool(self.datetime) and not Bool(other.datetime):
                return True
            return self.datetime.value().isoformat() == other.datetime.value().isoformat()

        return True
