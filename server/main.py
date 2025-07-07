import socket
import threading

from server import *

def handle_request(server:Server, request_header:RequestHeader, payload:bytes):
    """
    Checks the type of the client's request and
    calls the corresponding method on the server object to handle it.
    """
    if request_header.code == REQUEST_REGISTER:
        return server.register_client(request_header, payload)
    elif request_header.code == REQUEST_KEY_SHARE:
        return server.share_key(request_header, payload)
    elif request_header.code == REQUEST_LOGIN:
        return server.login(request_header, payload)
    elif request_header.code == REQUEST_SEND_FILE:
        return server.receive_file(request_header, payload)
    elif request_header.code == REQUEST_VALID_CRC:
        return server.confirm_valid_crc(request_header, payload)
    elif request_header.code == REQUEST_INVALID_CRC:
        return server.confirm_invalid_crc(request_header, payload)
    elif request_header.code == REQUEST_LAST_INVALID_CRC:
        return server.confirm_last_invalid_crc()
    else:
        return False

def handle_client(sock, address):
    """
    This function listens for messages from one client, unpacks and processes
    them safely, and keeps the connection open until the client or server ends it.
    """
    print(f"[NEW CONNECTION] : {address} connected.")
    server = Server(sock)

    while True:
        try:
            request_header_buf = recv_exact(sock, REQUEST_HDR_SIZE)
            request_header = RequestHeader()
            request_header.parse_from_bytes(request_header_buf)
            payload = bytes()

            if request_header.payload_size > 0:
                payload = recv_exact(sock, request_header.payload_size)

            if not handle_request(server, request_header, payload):
                break

        except Exception as e:
            print(f"*** EXCEPTION: {e}")
            break
    server.db_connection.close()
    sock.close()

def recv_exact(sock, num_bytes):
    buf = bytes()
    while len(buf) < num_bytes:
        chunk = sock.recv(num_bytes - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed early.")
        buf += chunk
    return buf


def main():
    if not os.path.exists(OUT_FILE_PATH):
        os.makedirs(OUT_FILE_PATH)

    port = SERVER_PORT
    try:
        port_file = open(INFO_FILE_NAME, "r")
        port = int(port_file.read())
        port_file.close()
    except FileNotFoundError as e:
        pass

    address = (SERVER_IP, port)

    """We're creating here a new socket object"""
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(address)

    server_sock.listen()
    print(f"[STARTING] : Server running on {SERVER_IP}:{port}")
    try:
        while True:
            """ the server accepts a client connection and handles it in a new thread."""
            sock, address = server_sock.accept()
            thread = threading.Thread(target=handle_client, args=(sock, address))
            thread.start()

    except Exception as e:
        print(f"[EXCEPTION] : {e}")

if __name__ == "__main__":
    main()
