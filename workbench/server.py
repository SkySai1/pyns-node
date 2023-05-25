#!./dns/bin/python3

import socket
import socketserver

class UDPserver(socketserver.BaseRequestHandler):

    def handle(self):
        data, sock = self.request
        sock.sendto(data, self.client_address)
        
if __name__ == "__main__":
    host = "127.0.0.2"
    port = 53
    addr = (host, port)
    with socketserver.ThreadingUDPServer(addr, UDPserver) as udp:
        print(f'Start to listen on {addr}')
        udp.serve_forever(0.1)
        udp.allow_reuse_address = True
