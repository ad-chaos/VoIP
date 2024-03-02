from packet_parser import VOIP_PORT
from libserver import Server

with Server(("localhost", VOIP_PORT)) as server:
    print(f"Server ready on port: {VOIP_PORT}")
    server.serve_forever()
