#!./dns/bin/python3

import asyncio
import socket

class MyUDPServer(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        # Обработка принятых данных
        self.transport.sendto(data, addr)

class MyTCPServer(asyncio.Protocol):
    def connection_made(self, transport):
        self.transport = transport

    def data_received(self, data):
        # Обработка принятых данных
        self.transport.write(data)

def udpecho():
    addr = ('127.0.0.2', 53)
    loop = asyncio.new_event_loop()
    listen = loop.create_datagram_endpoint(MyUDPServer, addr)
    transport, protocol = loop.run_until_complete(listen)

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    transport.close()
    loop.close()


def tcpecho():
    addr = ('127.0.0.2', 53)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(addr)
    loop = asyncio.get_event_loop()
    coro = loop.create_server(MyTCPServer, sock=s)
    server = loop.run_until_complete(coro)
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close() 

if __name__ == "__main__":
    udpecho()
