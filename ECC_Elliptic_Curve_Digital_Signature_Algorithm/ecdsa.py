#!/usr/bin/env python3
import codecs, hashlib, os, sys
from secp256r1 import curve
from pyasn1.codec.der import decoder

def ib(i, length=False):
    # Convertit un entier en bytes
    b = b''
    if length is False:
        length = (i.bit_length() + 7) // 8
    for _ in range(length):
        b = bytes([i & 0xff]) + b
        i >>= 8
    return b

def bi(b):
    # Convertit bytes en entier
    i = 0
    for char in b:
        i <<= 8
        i |= char
    return i

# --------------- ASN.1 DER encoder
def asn1_len(content):
    if isinstance(content, bytes):
        length = len(content)
    else:
        length = content  
    if length <= 127:
        return bytes([length])
    length_bytes = int_to_bytestring(length)
    length_prefix = 0x80 | len(length_bytes)
    return bytes([length_prefix]) + length_bytes

def int_to_bytestring(i):
    if i == 0:
        return b'\x00'
    byte_list = []
    while i > 0:
        byte_list.append(i & 0xFF) 
        i >>= 8
    byte_list.reverse()
    return bytes(byte_list)

def asn1_integer(i):
    if i == 0:
        return bytes([0x02, 0x01, 0x00])
    iByte = int_to_bytestring(i)
    if iByte[0] & 0x80:
        iByte = b'\x00' + iByte
    return bytes([0x02]) + asn1_len(iByte) + iByte

def asn1_sequence(der):
    return bytes([0x30]) + asn1_len(len(der)) + der
# --------------- ASN.1 DER encoder end

def pem_to_der(content):
    # converts PEM content (if it is PEM) to DER
    if content.startswith(b'-----'):
        content = content.replace(b"-----BEGIN PUBLIC KEY-----", b"")
        content = content.replace(b"-----END PUBLIC KEY-----", b"")
        content = content.replace(b"-----BEGIN PRIVATE KEY-----", b"")
        content = content.replace(b"-----END PRIVATE KEY-----", b"")
        content = codecs.decode(content, 'base64')
    return content

def get_privkey(filename):
    # reads EC private key file and returns the private key integer (d)
    with open(filename, "rb") as f:
        key_data = pem_to_der(f.read())
    key, _ = decoder.decode(key_data)
    ec_priv, _ = decoder.decode(bytes(key[2]))
    d = bi(bytes(ec_priv[1]))
    return d

def get_pubkey(filename):
    # reads EC public key file and returns coordinates (x, y) of the public key point
    with open(filename, "rb") as f:
        key_data = pem_to_der(f.read())
    key, _ = decoder.decode(key_data)
    pub_bitstring = key[1].asOctets()
    # if the public key is in uncompressed format, it should start with 0x04
    if pub_bitstring[0] == 4:
        if len(pub_bitstring) != 1 + 2 * 32:
            print("Error: uncompressed point has incorrect length.")
            return [None, None]
        x = int.from_bytes(pub_bitstring[1:33], "big")
        y = int.from_bytes(pub_bitstring[33:65], "big")
        Q = [x, y]
    elif pub_bitstring[0] in (2, 3):
        Q = curve.decompress(pub_bitstring)
    else:
        print("Unrecognized public key format.")
        return [None, None]
    return Q

def read_file(filename):
    # reads the content of a file
    with open(filename, "rb") as f:
        return f.read()

def write_file(filename, data):
    # writes data to a file
    with open(filename, "wb") as f:
        f.write(data)

def ecdsa_sign(keyfile, filetosign, signaturefile):
    # get the private key
    d = get_privkey(keyfile)
    file_data = read_file(filetosign)

    # calculate SHA-384 hash of the file to be signed
    h_digest = hashlib.sha384(file_data).digest()
    # truncate the hash value to the curve size
    h_bytes = h_digest[:32]
    if len(h_bytes) < 32:
        h_bytes = b'\x00' * (32 - len(h_bytes)) + h_bytes
    # convert hash to integer
    h = bi(h_bytes)

    # generates a random nonce k valid in [1, n-1]
    k = bi(os.urandom(64)) % curve.n
    R = curve.mul(curve.g, k)
    # calculate ECDSA signature components r and s
    r = R[0] % curve.n
    k_inv = pow(k, -1, curve.n)
    s = (k_inv * (h + r * d)) % curve.n
    if s == 0:
        print("Nonce regenerated (s == 0)")
        return ecdsa_sign(keyfile, filetosign, signaturefile)
    # DER-encode r and s
    sig = asn1_sequence(asn1_integer(r) + asn1_integer(s))
    # write DER structure to file
    write_file(signaturefile, sig)

def ecdsa_verify(keyfile, signaturefile, filetoverify):
    # prints "Verified OK" or "Verification failure"
    Q = get_pubkey(keyfile)
    file_data = read_file(filetoverify)
    h_digest = hashlib.sha384(file_data).digest()
    
    h_bytes = h_digest[:32]
    if len(h_bytes) < 32:
        h_bytes = b'\x00' * (32 - len(h_bytes)) + h_bytes
    h = int.from_bytes(h_bytes, "big")
    # Recup r, s value
    sig_data = read_file(signaturefile)
    sig, _ = decoder.decode(sig_data)
    r, s = int(sig[0]), int(sig[1])
    # Calcul R with pow function for inverse
    s_inv = pow(s, -1, curve.n)
    u1 = (h * s_inv) % curve.n
    u2 = (r * s_inv) % curve.n

    R1 = curve.mul(curve.g, u1)
    R2 = curve.mul(Q, u2)
    R = curve.add(R1, R2)

    # verifies if the computed r matches the signature's r
    if R[0] % curve.n == r:
        print("Verified OK")
    else:
        print("Verification failure")

def usage():
    print("Usage:")
    print("  sign <private key file> <file to sign> <signature output file>")
    print("  verify <public key file> <signature file> <file to verify>")
    sys.exit(1)

if len(sys.argv) != 5:
    usage()
elif sys.argv[1] == 'sign':
    ecdsa_sign(sys.argv[2], sys.argv[3], sys.argv[4])
elif sys.argv[1] == 'verify':
    ecdsa_verify(sys.argv[2], sys.argv[3], sys.argv[4])
else:
    usage()
