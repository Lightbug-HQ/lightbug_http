# TODO: Apply this to request/response structs
@fieldwise_init
@register_passable("trivial")
struct HttpVersion(EqualityComparable, Stringable):
    var _v: Int

    fn __init__(out self, version: String) raises:
        self._v = Int(version[version.find("/") + 1])

    fn __eq__(self, other: Self) -> Bool:
        return self._v == other._v

    fn __ne__(self, other: Self) -> Bool:
        return self._v != other._v

    fn __eq__(self, other: Int) -> Bool:
        return self._v == other

    fn __ne__(self, other: Int) -> Bool:
        return self._v != other

    fn __str__(self) -> String:
        # Only support version 1.1 so don't need to account for 1.0
        v = "1.1" if self._v == 1 else String(self._v)
        return "HTTP/" + v
