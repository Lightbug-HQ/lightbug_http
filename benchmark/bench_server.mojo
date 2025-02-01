from lightbug_http.server import Server
from lightbug_http.service import TechEmpowerRouter


def main():
    try:
        var server = Server(tcp_keep_alive=True)
        var handler = TechEmpowerRouter()
        server.listen_and_serve("localhost:8080", handler)
    except e:
        print("Error starting server: " + e.__str__())
        return
