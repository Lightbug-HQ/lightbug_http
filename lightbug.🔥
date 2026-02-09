from lightbug_http import Welcome
from lightbug_http.server import Server
from os.env import getenv


fn main() raises:
    var server = Server()
    var handler = Welcome()

    var host = getenv("DEFAULT_SERVER_HOST", "localhost")
    var port = getenv("DEFAULT_SERVER_PORT", "8080")

    server.listen_and_serve(host + ":" + port, handler)
