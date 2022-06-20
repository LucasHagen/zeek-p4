import socket
import os
import signal
import sys
from time import sleep


def valid_type(t):
    t = t.lower()
    return t == "c" or t == "client" or t == "server" or t == "s"


if len(sys.argv) < 4 or int(sys.argv[3]) == 0 or not valid_type(sys.argv[1]):
    print("Error. Correct Usage:")
    print(" |_ server: python3 %s server|s <ip> <port>" %
          os.path.basename(__file__))
    print(" |_ client: python3 %s client|c <ip> <port>" %
          os.path.basename(__file__))
    exit(1)

HOST = sys.argv[2]
PORT = int(sys.argv[3])
IS_SERVER = sys.argv[1].lower().startswith("s")

socket_global = None


def handler(signum, frame):
    global socket_global
    socket_global.close()
    socket_global = None
    print("")
    print("Closed socket")
    print("Done!")
    exit(0)


signal.signal(signal.SIGINT, handler)

if IS_SERVER:
    print("Started server on %s:%s" % (HOST, PORT))

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        socket_global = s
        s.bind((HOST, PORT))
        s.listen()

        conn, addr = s.accept()
        with conn:
            print("Connected by %s" % str(addr))
            conn.sendall("220 (fake_ftp 0.0.1)".encode('ascii'))

            while True:
                data = conn.recv(1024)
                if not data:
                    break
                cmd = data.decode('ascii').split(" ")

                if cmd[0].lower() == "user":
                    conn.sendall(
                        "331 Please specify the password.".encode('ascii'))
                elif cmd[0].lower() == "pass":
                    sleep(1)
                    conn.sendall("530 Login incorrect.".encode('ascii'))
                else:
                    conn.sendall(
                        "530 Please login with USER and PASS.".encode('ascii'))

else:
    print("Connecting to %s:%s" % (HOST, PORT))

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        socket_global = s
        s.connect((HOST, PORT))

        while True:
            print("Waiting for server")
            data = s.recv(1024)
            if not data:
                break

            print("Received: '%s'" % data.decode('ascii'))

            cmd = input()
            s.sendall(cmd.encode('ascii'))
            print("Sent '%s'" % cmd)


print("Done!")
