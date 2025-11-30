@fieldwise_init
struct SameSite(Copyable, Movable, Stringable):
    var value: UInt8

    alias none = SameSite(0)
    alias lax = SameSite(1)
    alias strict = SameSite(2)

    alias NONE = "none"
    alias LAX = "lax"
    alias STRICT = "strict"

    @staticmethod
    fn from_string(str: String) -> Optional[Self]:
        if str == SameSite.NONE:
            return materialize[SameSite.none]()
        elif str == SameSite.LAX:
            return materialize[SameSite.lax]()
        elif str == SameSite.STRICT:
            return materialize[SameSite.strict]()
        return None

    fn __eq__(self, other: Self) -> Bool:
        return self.value == other.value

    fn __str__(self) -> String:
        if self.value == 0:
            return materialize[SameSite.NONE]()
        elif self.value == 1:
            return materialize[SameSite.LAX]()
        else:
            return materialize[SameSite.STRICT]()
