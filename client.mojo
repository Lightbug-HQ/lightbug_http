from lightbug_http.client import Client

from lightbug_http import *


fn test_request(mut client: Client) raises -> None:
    var uri = URI.parse("google.com")
    var headers = Headers(Header("Host", "google.com"))
    var request = HTTPRequest(uri, headers)
    var response = client.do(request^)

    # print status code
    print("Response:", response.status_code)

    print(response.headers)

    print(
        "Is connection set to connection-close? ", response.connection_close()
    )

    # print body
    print(to_string(response.body_raw))


fn main() -> None:
    try:
        var client = Client()
        test_request(client)
    except e:
        print(e)
