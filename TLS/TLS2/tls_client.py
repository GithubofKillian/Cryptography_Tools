#!/usr/bin/env python3

import argparse, codecs, hmac, socket, sys, time, os, datetime
from hashlib import sha1, sha256
from Cryptodome.Cipher import ARC4
from pyasn1.codec.der import decoder  # do not use any other imports/libraries
from urllib.parse import urlparse

# took x.y hours (please specify here how much time your solution required)

# parse arguments
parser = argparse.ArgumentParser(description='TLS v1.2 client')
parser.add_argument('url', type=str, help='URL to request')
parser.add_argument('--certificate', type=str, help='File to write PEM-encoded server certificate')
args = parser.parse_args()

def get_pubkey_certificate(cert):
    # reads the certificate and returns (n, e)
    cert_parsed = decoder.decode(cert)
    #print("Decoded Certificate:", cert_parsed)

    # Extract the part of the Certificate
    field_certificate = cert_parsed[0][0]
    #print("field_certificate:", field_certificate)

    # Explore and print each field in the sequence for better visibility
    #for index, field in enumerate(tbs_certificate):
        #print(f"Field-{index}:", field)

    # seems to be 6th field
    field_public_key_info = field_certificate[6]
    #print("field_public_key_info:", field_public_key_info)

    # Extract the public key
    public_key = field_public_key_info[1]
    #print("public_key:", public_key)

    # Convert the public key to its DER encoded form (octets)
    key_bits = public_key.asOctets()
    #print("Key Bits:", key_bits.hex().upper())

    #decode using pyasn1
    rsa_key = decoder.decode(key_bits)
    #print("rsa key:",rsa_key)
    # RSA pk
    n, e = rsa_key[0][0], rsa_key[0][1]
    #print("n:",n,"e:",e)
    n = int(n)
    e = int(e)
    return n, e


def pkcsv15pad_encrypt(plaintext, n):
    # pad plaintext for encryption according to PKCS#1 v1.5
    k = (n.bit_length() + 7) // 8
    ps_len = k - 3 - len(plaintext)
    ps = b""
    while len(ps) < ps_len:
        b = os.urandom(1)
        if b != b'\x00':
            ps += b

    padded = b"\x00\x02" + ps + b"\x00" + plaintext
    return padded

def rsa_encrypt(cert, m):
    #modulus and exponent
    n, e = get_pubkey_certificate(cert)
    
    # Pad the message
    padded_m = pkcsv15pad_encrypt(m, n)
    m_int = bi(padded_m)
    
    # c = m^e mod n : RSA Enc
    cipher_int = pow(m_int, e, n)
    # convert to byte
    k = (n.bit_length() + 7) // 8
    cipher = ib(cipher_int, k)
    return cipher


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

def client_key_exchange():
    global server_cert, premaster, handshake_messages
    print("--> ClientKeyExchange()")
    #Two-byte length-prefixed
    premaster = b"\x03\x03" + os.urandom(46)
    
    # Encrypted using the public key from the server’s certificate
    encrypt_premaster = rsa_encrypt(server_cert, premaster)
    len_premaster_enc = len(encrypt_premaster).to_bytes(2, 'big')
    body = len_premaster_enc + encrypt_premaster
    
    #\x10 for ClientKeyExchange
    H_length = len(body).to_bytes(3, 'big')
    handshake = b"\x10" + H_length + body
    
    # \x16\x03\x03 for Handshake + version
    R_length = len(handshake).to_bytes(2, 'big')
    record = b"\x16\x03\x03" + R_length + handshake
    handshake_messages += handshake
    
    return record

# returns TLS record that contains ChangeCipherSpec message
def change_cipher_spec():
    print("--> ChangeCipherSpec()")
    # one byte body
    body = b"\x01"
    # \x14\x03\x03\x00\x01 for Contenttype, version, length and body
    record = b"\x14\x03\x03\x00\x01" + body
    return record

# returns TLS record that contains encrypted Finished handshake message
def finished():
    global handshake_messages, master_secret
    print("--> Finished()")
    client_verify = PRF(master_secret, b"client finished" + sha256(handshake_messages).digest(), 12)
    #Creating the hadshake message
    body = client_verify
    H_length = len(body).to_bytes(3, 'big')
    # 0x14 for finished
    handshake = b"\x14" + H_length + body  
    handshake_messages += handshake
    encrypted = encrypt(handshake, b"\x16", b"\x03\x03")
    R_length = len(encrypted).to_bytes(2, 'big')
    # \x16\x03\x03 for handshake + version
    record = b"\x16\x03\x03" + R_length + encrypted
    return record


# returns TLS record that contains encrypted Application data
def application_data(data):
    print("--> Application_data()")
    encrypted_data = encrypt(data, b"\x17", b"\x03\x03")
    record_length = len(encrypted_data).to_bytes(2, 'big')
    # 0x17 for app data
    record = b"\x17\x03\x03" + record_length + encrypted_data  
    print(data.decode().strip())
    return record

# parse TLS Handshake messages
def parsehandshake(r):
    global server_hello_done_received, server_random, server_cert, handshake_messages, server_change_cipher_spec_received, server_finished_received
    print("<--- Handshake()")
    # decrypt if encryption enabled
    if server_change_cipher_spec_received:
        r = decrypt(r, b"\x16", b"\x03\x03")

    # read Handshake message type and length from message header
    htype, hlength = r[0:1], bi(r[1:4])
    body = r[4:4+hlength]
    handshake = r[:4+hlength]
    handshake_messages+= handshake

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
        print(" [+] server timestamp:", datetime.datetime.utcfromtimestamp(int.from_bytes(gmt, "big")))

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

    elif htype == b"\x0b":
        print("	<--- Certificate()")
        #Certificate list length
        cert_list_len = bi(r[4:7])
        certs_data = r[7:7 + cert_list_len]

        #First certificate extraction
        first_cert_len = bi(certs_data[0:3])
        server_cert = certs_data[3:3 + first_cert_len]
        print(" [+] Server certificate length:", first_cert_len)

        #saving server_cert to pem format
        if args.certificate:
            pem = "-----BEGIN CERTIFICATE-----\n"
            b64 = codecs.encode(server_cert, 'base64').decode('ascii')
            b64_lines = [b64[i:i+64] for i in range(0, len(b64), 64)]
            pem += '\n'.join(b64_lines) + '\n'
            pem += "-----END CERTIFICATE-----\n"
            with open(args.certificate, 'w') as f:
                f.write(pem)
            print("	[+] Server certificate saved in:", args.certificate)

    elif htype == b"\x0e":
        print("	<--- ServerHelloDone()")
        #Read ServerHelloDone
        server_hello_done_received = True

    elif htype == b"\x14":
        print("	<--- Finished()")
        # hashmac of all Handshake messages except the current Finished message (obviously)
        verify_data_calc = PRF(master_secret, b"server finished" + sha256(handshake_messages[:-4-hlength]).digest(), 12)
        if server_verify!=verify_data_calc:
            print("[-] Server finished verification failed!")
            sys.exit(1)
    else:
        print("[-] Unknown Handshake Type:", htype.hex())
        sys.exit(1)

    # handle the case of several Handshake messages in one record
    leftover = r[4+len(body):]
    if len(leftover):
        parsehandshake(leftover)

# parses TLS record
def parserecord(r):
    global server_change_cipher_spec_received

    # parse TLS record header and pass the record body to the corresponding parsing method
    ctype = r[0:1]
    c = r[5:]

    # handle known types
    if ctype == b"\x16":

        parsehandshake(c)
    elif ctype == b"\x14":
        print("<--- ChangeCipherSpec()")
        server_change_cipher_spec_received = True
    elif ctype == b"\x15":
        print("<--- Alert()")
        level, desc = c[0], c[1]
        if level == 1:
            print("	[-] warning:", desc)
        elif level == 2:
            print("	[-] fatal:", desc)
            sys.exit(1)
        else:
            sys.exit(1)
    elif ctype == b"\x17":
        print("<--- Application_data()")
        data = decrypt(c, b"\x17", b"\x03\x03")
        print(data.decode().strip())
    else:
        print("[-] Unknown TLS Record type:", ctype.hex())
        sys.exit(1)

# PRF defined in TLS v1.2
def PRF(secret, seed, l):

    out = b""
    A = hmac.new(secret, seed, sha256).digest()
    while len(out) < l:
        out += hmac.new(secret, A + seed, sha256).digest()
        A = hmac.new(secret, A, sha256).digest()
    return out[:l]

# derives master_secret
def derive_master_secret():
    global premaster, master_secret, client_random, server_random
    master_secret = PRF(premaster, b"master secret" + client_random + server_random, 48)

# derives keys for encryption and MAC
def derive_keys():
    global premaster, master_secret, client_random, server_random
    global client_mac_key, server_mac_key, client_enc_key, server_enc_key, rc4c, rc4s

    key_block = PRF(master_secret, b"key expansion" + server_random + client_random, 136)
    mac_size = 20
    key_size = 16
    iv_size = 16

    client_mac_key = key_block[:mac_size]
    server_mac_key = key_block[mac_size:mac_size*2]
    client_enc_key = key_block[mac_size*2:mac_size*2+key_size]
    server_enc_key = key_block[mac_size*2+key_size:mac_size*2+key_size*2]

    rc4c = ARC4.new(client_enc_key)
    rc4s = ARC4.new(server_enc_key)

# HMAC SHA1 wrapper
def HMAC_sha1(key, data):
    return hmac.new(key, data, sha1).digest()

# calculates MAC and encrypts plaintext
def encrypt(plain, type, version):
    global client_mac_key, client_enc_key, client_seq, rc4c

    mac = HMAC_sha1(client_mac_key, ib(client_seq, 8) + type + version + ib(len(plain), 2) + plain)
    ciphertext = rc4c.encrypt(plain + mac)
    client_seq+= 1
    return ciphertext

# decrypts ciphertext and verifies MAC
def decrypt(ciphertext, type, version):
    global server_mac_key, server_enc_key, server_seq, rc4s

    d = rc4s.decrypt(ciphertext)
    mac = d[-20:]
    plain = d[:-20]

    # verify MAC
    mac_calc = HMAC_sha1(server_mac_key, ib(server_seq, 8) + type + version + ib(len(plain), 2) + plain)
    if mac!=mac_calc:
        print("[-] MAC verification failed!")
        sys.exit(1)
    server_seq+= 1
    return plain

# read from the socket full TLS record
def readrecord():
    record = b""

    # read TLS record header (5 bytes)
    for _ in range(5):
        buf = s.recv(1)
        if not buf:
            print("[-] socket closed!")
            exit(1)
        record += buf

    # find data length
    datalen = bi(record[3:5])

    # read TLS record body
    for _ in range(datalen):
        buf = s.recv(1)
        if not buf:
            print("[-] socket closed!")
            exit(1)
        record += buf

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

client_random = b""	# will hold client randomness
server_random = b""	# will hold server randomness
server_cert = b""	# will hold DER encoded server certificate
premaster = b""		# will hold 48 byte pre-master secret
master_secret = b""	# will hold master secret
handshake_messages = b"" # will hold concatenation of handshake messages

# client/server keys and sequence numbers
client_mac_key = b""
server_mac_key = b""
client_enc_key = b""
server_enc_key = b""
client_seq = 0
server_seq = 0

# client/server RC4 instances
rc4c = b""
rc4s = b""

s.connect((host, port))
s.send(client_hello())

server_hello_done_received = False
server_change_cipher_spec_received = False
server_finished_received = False

while not server_hello_done_received:
    parserecord(readrecord())

s.send(client_key_exchange())
s.send(change_cipher_spec())
derive_master_secret()
derive_keys()
s.send(finished())

while not server_finished_received:
    parserecord(readrecord())

s.send(application_data(b"GET / HTTP/1.0\r\n\r\n"))
parserecord(readrecord())

print("[+] Closing TCP connection!")
s.close()
