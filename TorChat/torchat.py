#!/usr/bin/env python3

# sudo apt install python3-socks
import argparse
import socks
import socket
import sys
import secrets # https://docs.python.org/3/library/secrets.html

# do not use any other imports/libraries

# took 3/4 hours (please specify here how much time your solution required)


# parse arguments
parser = argparse.ArgumentParser(description='TorChat client')
parser.add_argument('--myself', required=True, type=str, help='My TorChat ID')
parser.add_argument('--peer', required=True, type=str, help='Peer\'incoming_socket TorChat ID')
args = parser.parse_args()

# route outgoing connections through Tor
socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, "127.0.0.1", 9050)
socket.socket = socks.socksocket

# reads and returns torchat command from the socket
def read_torchat_cmd(incoming_socket):
    # read until newline
    data = b""
    while not data.endswith(b"\n"):
        try:
            chunk = incoming_socket.recv(1)
            if not chunk:
                break
            data += chunk
        except:
            break
    # return command
    cmd = data.decode().strip()
    return cmd

# prints torchat command and sends it
def send_torchat_cmd(outgoing_socket, cmd):
    print("[+] Sending: " + cmd.strip())
    try:
        outgoing_socket.send((cmd.strip() + "\n").encode())
    except Exception as e:
        print("[!] Failed to send:", e)

# mycookie creation
mycookie = str(secrets.randbits(128))
# connecting to peer
peer_socket = socket.socket()
peer_address = args.peer + ".onion"
peer_port = 11009
print(f"[+] Connecting to peer {peer_address}")
peer_socket.connect((peer_address, peer_port))

# start listening
sserv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sserv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sserv.bind(('127.0.0.1', 8888))
sserv.listen(0)

# sending ping
send_torchat_cmd(peer_socket, f"ping {args.myself} {mycookie}")

# listening for the incoming connection
print("[+] Listening...")
(incoming_socket, address) = sserv.accept()
print("[+] Client %s:%s" % (address[0], address[1]))

incoming_authenticated = False
status_received = False
cookie_peer = ""
peer_id_verified = False
pong_received = False

# the main loop for processing the received commands
while True:
    cmdr = read_torchat_cmd(incoming_socket)
    cmd = cmdr.split(' ')

    if cmd[0]=='ping':
        print(f"[+] Received: ping {cmd[1]} {cmd[2]}")
        peer_id = cmd[1]
        cookie_peer = cmd[2]

        if peer_id != args.peer:
            print("[-] Peer ID mismatch. Expected:", args.peer, "Got:", peer_id)
            break

        peer_id_verified = True

    elif cmd[0] == "pong":
        if cmd[1] == mycookie:
            print(f"[+] Received: pong {cmd[1]}")
            pong_received = True
        continue

    # All those case can append before or after the incoming_authenticated      
    elif cmd[0] == "client":
        print(f"[+] Received: client {cmd[1]}")
        continue

    elif cmd[0] == "version":
        print(f"[+] Received: version {cmd[1]}")
        continue
    
    # No profile name for my tests
    elif cmd[0] == "profile_name":
        print(f"[+] Received: profile_name {cmd[1]}")
        continue
    
    elif cmd[0] == "status":
        print(f"[+] Received: status {cmd[1]}")
        continue

    # authenticate after peer ping + pong are received
    if not incoming_authenticated and peer_id_verified and pong_received:
        incoming_authenticated = True
        print("[+] Incoming connection authenticated!")
        send_torchat_cmd(peer_socket, f"pong {cookie_peer}")
        send_torchat_cmd(peer_socket, "add_me")
        send_torchat_cmd(peer_socket, "status available")
        send_torchat_cmd(peer_socket, "profile_name Alice")

    elif incoming_authenticated:
        if cmd[0] == "message":
            print(f"[+] Received: {' '.join(cmd[1:])}")
            print(f"[?] Enter message: ", end="")
            user_input = input().strip()
            if user_input:
                send_torchat_cmd(peer_socket, f"message {user_input}")

        

