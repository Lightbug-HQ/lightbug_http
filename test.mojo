from lightbug_http.http.json import JsonOK, json_decode, JsonError, JsonSerializable, JsonDeserializable
from emberjson import serialize, deserialize

@fieldwise_init
struct Message(JsonSerializable, Defaultable, Movable):
    var message: String

    fn __init__(out self):
        self.message = ""

fn main() raises:
    # Test serialization via JsonOK
    var msg = Message("Hello, World!")
    var res = JsonOK(msg)
    print("status:", res.status_code)
    print("body:", String(res.get_body()))

    # Test deserialization
    var parsed = deserialize[Message]('{"message": "from JSON"}')
    print("deserialized:", parsed.message)