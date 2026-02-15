import concurrent.futures
import requests
import socket
import time

session = requests.Session()

print("\n~~~ Testing redirect ~~~")
response = session.get("http://127.0.0.1:8080/redirect", allow_redirects=True)
assert response.status_code == 200
assert response.text == "yay you made it"

print("\n~~~ Testing close connection ~~~")
response = session.get(
    "http://127.0.0.1:8080/close-connection", headers={"connection": "close"}
)
assert response.status_code == 200
assert response.text == "connection closed"

print("\n~~~ Testing internal server error ~~~")
response = session.get(
    "http://127.0.0.1:8080/error", headers={"connection": "keep-alive"}
)
assert response.status_code == 500

print("\n~~~ Testing large headers ~~~")
large_headers = {
    f"X-Custom-Header-{i}": "value" * 100  # long value
    for i in range(8)  # minimum number to exceed default buffer size (4096)
}
response = session.get(
    "http://127.0.0.1:8080/large-headers", headers=large_headers
)
assert response.status_code == 200

print("\n~~~ Testing parallel connections ~~~")


def fetch(path):
    return requests.get(f"http://127.0.0.1:8080{path}")


with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
    futures = [executor.submit(fetch, f"/?n={i}") for i in range(4)]
    results = concurrent.futures.wait(futures, timeout=5)
    assert len(results.done) == 4, f"Only {len(results.done)}/4 parallel requests completed within 5s"
    for f in results.done:
        assert f.result().status_code == 200

print("\n~~~ Testing content-length mismatch (smaller) ~~~")


def test_content_length_smaller():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", 8080))
    s.sendall(
        b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\n\r\nOnly"
        b" sending 20 bytes"
    )
    time.sleep(1)
    s.close()


test_content_length_smaller()
time.sleep(1)

print("\n~~~ All tests completed ~~~")
