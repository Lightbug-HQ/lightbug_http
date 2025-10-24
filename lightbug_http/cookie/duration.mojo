@fieldwise_init
struct Duration(Copyable, Movable):
    var total_seconds: Int

    fn __init__(out self, seconds: Int = 0, minutes: Int = 0, hours: Int = 0, days: Int = 0):
        self.total_seconds = seconds
        self.total_seconds += minutes * 60
        self.total_seconds += hours * 60 * 60
        self.total_seconds += days * 24 * 60 * 60

    @staticmethod
    fn from_string(str: String) -> Optional[Self]:
        try:
            return Duration(seconds=Int(str))
        except:
            return Optional[Self](None)
