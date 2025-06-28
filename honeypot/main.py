import socket
import threading
from .handlers import client_handle

def honeypot(address='0.0.0.0', port=2222, username=None, password=None, tarpit=False):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((address, port))
    sock.listen(100)

    print(f"SSH honeypot listening on {address}:{port}")

    while True:
        try:
            client, addr = sock.accept()
            t = threading.Thread(target=client_handle, args=(client, addr, username, password, tarpit))
            t.start()
        except Exception as e:
            print("!!! Exception - Failed to accept connection !!!")
            print(e)