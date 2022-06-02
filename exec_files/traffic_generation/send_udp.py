import socket
import sys

if len(sys.argv) < 3 or int(sys.argv[2]) == 0:
    print("Error. Correct Usage: python3 send_udp.py <ip> <port> [source_port]")
    exit(1)

UDP_IP = sys.argv[1]
UDP_PORT = int(sys.argv[2])
UDP_SOURCE_PORT = None if len(sys.argv) < 4 or int(sys.argv[3]) == 0 else int(sys.argv[3])
MESSAGE = "Hello, World!"


print("UDP target IP:", UDP_IP)
print("UDP target port:", UDP_PORT)
if UDP_SOURCE_PORT != None:
    print("UDP source port:", UDP_SOURCE_PORT)
print("message:", MESSAGE)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP

if UDP_SOURCE_PORT != None:
    sock.bind(('0.0.0.0', UDP_SOURCE_PORT))

sock.sendto(bytes(MESSAGE, "utf-8"), (UDP_IP, UDP_PORT))

sock.close()
