#!/usr/bin/env python3

import argparse, codecs, datetime, os, socket, sys, time # do not use any other imports/libraries
from urllib.parse import urlparse

# took 3 hours (please specify here how much time your solution required)

# parse arguments
parser = argparse.ArgumentParser(description='TLS v1.2 client')
parser.add_argument('url', type=str, help='URL to request')
parser.add_argument('--certificate', type=str, help='File to write PEM-encoded server certificate')
args = parser.parse_args()

def ib(i, length=False):
    # converts integer to bytes
    b = b''
    if length==False:
        length = (i.bit_length()+7)//8
    for _ in range(length):
        b = bytes([i & 0xff]) + b
        i >>= 8
    return b

def bi(b):
    # converts bytes to integer
    i = 0
    for byte in b:
        i <<= 8
        i |= byte
    return i

# returns TLS record that contains ClientHello Handshake message
def client_hello():

    print("--> ClientHello()")

    # Protocol version: 0x0303 (for TLS v1.2)
    version = b"\x03\x03"
    sessid = b"\x00"
    compression = b"\x01" + b"\x00"

    timestamp = int(time.time()).to_bytes(4, 'big')
    random = timestamp + os.urandom(28)

    # list of cipher suites the client supports
    csuite = b"\x00\x05" # TLS_RSA_WITH_RC4_128_SHA
    csuite+= b"\x00\x2f" # TLS_RSA_WITH_AES_128_CBC_SHA
    csuite+= b"\x00\x35" # TLS_RSA_WITH_AES_256_CBC_SHA
    csuite_length = len(csuite).to_bytes(2, 'big')

    body = version + random + sessid + csuite_length + csuite + compression

    # add Handshake message header
    handshake_length = len(body).to_bytes(3, 'big')
    handshake = b"\x01" + handshake_length + body

    # add record layer header
    record_length = len(handshake).to_bytes(2, 'big')
    record = b"\x16" + version + record_length + handshake

    return record

# returns TLS record that contains 'Certificate unknown' fatal Alert message
def alert():
    print("--> Alert()")

    # add alert message
    alert_message = b"\x02" + b"\x2E"
    # add record layer header
    record = b"\x15" + b"\x03\x03" + len(alert_message).to_bytes(2, 'big') + alert_message
    return record

# parse TLS Handshake messages
def parsehandshake(r):
    global server_hello_done_received

    print("<--- Handshake()")

    # read Handshake message type and length from message header
    htype = r[0:1]
    hlen = r[1:4]
    
    if htype == b"\x02":
        print("	<--- ServerHello()")
        
        #Read ServerHello
        version = r[4:6]
        server_random = r[6:38]
        gmt = r[6:10]
        sessid_length = r[38:39]
        sessid = r[39:39 + bi(sessid_length)]
        cipher = r[39+ bi(sessid_length):41 + bi(sessid_length)]
        compression = r[41 + bi(sessid_length):42 + bi(sessid_length)]

        print("	[+] server randomness:", server_random.hex().upper())
        print("	[+] server timestamp:", gmt)
        print("	[+] TLS session ID:", sessid.hex().upper())

        if cipher==b"\x00\x2f":
            print("	[+] Cipher suite: TLS_RSA_WITH_AES_128_CBC_SHA")
        elif cipher==b"\x00\x35":
            print("	[+] Cipher suite: TLS_RSA_WITH_AES_256_CBC_SHA")
        elif cipher==b"\x00\x05":
            print("	[+] Cipher suite: TLS_RSA_WITH_RC4_128_SHA")
        else:
            print("[-] Unsupported cipher suite selected:", cipher.hex())
            sys.exit(1)

        if compression!=b"\x00":
            print("[-] Wrong compression:", compression.hex())
            sys.exit(1)

    elif htype == b"\x0b":
        print("	<--- Certificate()")
        #Read Certificate
        cert_len = bi(r[4:7])
        cert = r[7:7 + cert_len]
        print("	[+] Server certificate length:", cert_len)
        if args.certificate:
            with open(args.certificate, 'wb') as f:
                f.write(cert)
            print("	[+] Server certificate saved in:", args.certificate)
    elif htype == b"\x0e":
        print("	<--- ServerHelloDone()")
        #Read ServerHelloDone
        server_hello_done_received = True
    else:
        print("[-] Unknown Handshake type:", htype.hex())
        sys.exit(1)

    # handle the case of several Handshake messages in one record
    hlen = bi(hlen)
    msg_end = 4 + hlen
    leftover = r[msg_end:]
    if len(leftover):
        parsehandshake(leftover)

# parses TLS record
def parserecord(r):
    # parse TLS record header and pass the record body to the corresponding parsing method (i.e., parsehandshake())
    Type = r[0:1]
    Version = r[1:3]
    Length = r[3:5]
    Data = r[5:]
    if Type == b"\x16":
        parsehandshake(Data)
    else:
        print("[-] Unknown TLS record type:", Type.hex())
        sys.exit(1)

# read from the socket full TLS record
def readrecord():
    global s
    record = b""

    # read the TLS record header (5 bytes)
    record = s.recv(5)
    if len(record) != 5:
        return None
    # find data length
    Length = bi(record[3:5])
    # read the TLS record body
    record += s.recv(Length)
    return record

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
url = urlparse(args.url)
host = url.netloc.split(':')
if len(host) > 1:
    port = int(host[1])
else:
    port = 443
host = host[0]
path = url.path

s.connect((host, port))
s.send(client_hello())

server_hello_done_received = False
while not server_hello_done_received:
    parserecord(readrecord())
s.send(alert())

print("[+] Closing TCP connection!")
s.close()
