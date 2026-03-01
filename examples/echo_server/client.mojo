import floki


fn main() raises:
    var response = floki.post(
        "localhost:8080",
        headers={"Content-Type": "text/plain"},
        data="Hello, Echo Server!".as_bytes()
    )
    print(response.body.as_string_slice())

    response = floki.post(
        "localhost:8080",
        headers={"Content-Type": "application/json"},
        data={"message": "Hello, Echo Server!"}
    )
    print(response.body.as_json())
