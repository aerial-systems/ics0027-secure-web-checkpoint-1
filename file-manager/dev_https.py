"""Loopback-only HTTPS development server; use generated certificates, never production."""

import os
import ssl
from pathlib import Path
from wsgiref.simple_server import WSGIRequestHandler, make_server

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
os.environ["DEV_TLS"] = "1"
from django.core.wsgi import get_wsgi_application


class HTTPSHandler(WSGIRequestHandler):
    def get_environ(self):
        environ = super().get_environ()
        environ["HTTPS"] = "on"
        environ["wsgi.url_scheme"] = "https"
        return environ


root = Path(__file__).resolve().parent
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = ssl.TLSVersion.TLSv1_2
context.load_cert_chain(
    root / "private-storage/localhost.pem", root / "private-storage/localhost.key"
)
server = make_server(
    "127.0.0.1", 8443, get_wsgi_application(), handler_class=HTTPSHandler
)
server.socket = context.wrap_socket(server.socket, server_side=True)
print("Development HTTPS listening on https://localhost:8443/", flush=True)
server.serve_forever()
