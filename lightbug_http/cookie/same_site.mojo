struct SameSite(Stringable, Copyable, Movable, ImplicitlyCopyable):
    var value: UInt8

    fn __init__(out self, value: UInt8):
        self.value = value

    alias none = SameSite(0)
    alias lax = SameSite(1)
    alias strict = SameSite(2)

    alias NONE = "none"
    alias LAX = "lax"
    alias STRICT = "strict"

    @staticmethod
    fn from_string(str: String) -> Optional[Self]:
        if str == SameSite.NONE:
            return SameSite.none
        elif str == SameSite.LAX:
            return SameSite.lax
        elif str == SameSite.STRICT:
            return SameSite.strict
        return None

    fn __eq__(self, other: Self) -> Bool:
        return self.value == other.value

    fn __str__(self) -> String:
        if self.value == 0:
            return SameSite.NONE
        elif self.value == 1:
            return SameSite.LAX
        else:
            return SameSite.STRICT
