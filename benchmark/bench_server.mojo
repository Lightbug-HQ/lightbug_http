from lightbug_http.server import Server
from lightbug_http.service import TechEmpowerRouter


fn main() raises:
    var server = Server(tcp_keep_alive=True)
    var handler = TechEmpowerRouter()
    server.listen_and_serve("localhost:8080", handler)
