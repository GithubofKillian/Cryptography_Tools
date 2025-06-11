#!/usr/bin/env python3

import codecs, hashlib, os, sys
from pyasn1.codec.der import decoder

def ib(i, length=False):
    # converts integer to bytes (big-endian)
    b = b''
    if length is False:
        length = (i.bit_length()+7)//8
    for _ in range(length):
        b = bytes([i & 0xff]) + b
        i //= 256
    return b

def bi(b):
    # converts bytes to integer (big-endian)
    i = 0
    for byte in b:
        i = (i << 8) | byte
    return i

#==== ASN1 encoder start ====
def encode_length(length):
    if length < 128:
        return bytes([length])
    else:
        length_bytes = ib(length)
        return bytes([0x80 | len(length_bytes)]) + length_bytes

def encode_integer(value):
    value_bytes = ib(value)
    if value_bytes[0] & 0x80:
        value_bytes = b'\x00' + value_bytes
    return b'\x02' + encode_length(len(value_bytes)) + value_bytes

def encode_sequence(*elements):
    body = b''.join(elements)
    return b'\x30' + encode_length(len(body)) + body

def encode_bitstring(value):
    return b'\x03' + encode_length(len(value) + 1) + b'\x00' + value

def encode_octetstring(value):
    return b'\x04' + encode_length(len(value)) + value
#==== ASN1 encoder end ====

def encode_null():
    return b'\x05\x00'

def encode_oid(oid_str):
    """Encodes an OID string (e.g. "2.16.840.1.101.3.4.2.1") in DER."""
    parts = [int(x) for x in oid_str.split('.')]
    first_byte = 40 * parts[0] + parts[1]
    encoded = bytes([first_byte])
    for number in parts[2:]:
        subid = []
        if number == 0:
            subid.append(0)
        else:
            while number:
                subid.insert(0, number & 0x7F)
                number //= 128
        for j in range(len(subid)-1):
            subid[j] |= 0x80
        encoded += bytes(subid)
    return b'\x06' + encode_length(len(encoded)) + encoded

def pem_to_der(content):
    # converts PEM content to DER by removing header/footer and decoding Base64
    lines = [line.strip() for line in content.splitlines() if line and not line.startswith("-----")]
    b64data = "".join(lines)
    return codecs.decode(b64data.encode('utf-8'), 'base64')

def get_pubkey(filename):
    # reads public key file (SubjectPublicKeyInfo PEM) and returns (N, e)
    with open(filename, 'r') as f:
        pem_data = f.read()
    der_data = pem_to_der(pem_data)
    spki, _ = decoder.decode(der_data)
    # spki[1] is a BIT STRING containing the RSAPublicKey DER
    rsa_der = spki[1].asOctets()
    rsa_key, _ = decoder.decode(rsa_der)
    n = int(rsa_key[0])
    e = int(rsa_key[1])
    return n, e

def get_privkey(filename):
    # reads private key file (PKCS#8 PEM/DER or traditional RSAPrivateKey DER)
    with open(filename, 'rb') as f:
        data = f.read()
    if data.startswith(b'-----'):
        data_str = data.decode('utf-8')
        lines = [line.strip() for line in data_str.splitlines() if line and not line.startswith("-----")]
        b64 = "".join(lines)
        der_data = codecs.decode(b64.encode('utf-8'), 'base64')
    else:
        der_data = data
    # Try decoding as PKCS#8
    pkcs8, _ = decoder.decode(der_data)
    if len(pkcs8) >= 3:
        priv_octet = pkcs8[2]
        rsa_der = priv_octet.asOctets()
        rsa_key, _ = decoder.decode(rsa_der)
    else:
        # Otherwise decode directly as RSAPrivateKey
        rsa_key, _ = decoder.decode(der_data)
    n = int(rsa_key[1])
    d = int(rsa_key[3])
    return n, d

def pkcsv15pad_encrypt(plaintext, n):
    # pad plaintext for encryption according to PKCS#1 v1.5:
    # Format: 0x00 || 0x02 || PS (nonzero random bytes) || 0x00 || M
    k = (n.bit_length() + 7) // 8
    if len(plaintext) > k - 11:
        raise ValueError("Message too long for the given modulus")
    ps = b''
    while len(ps) < k - len(plaintext) - 3:
        new_byte = os.urandom(1)
        if new_byte != b'\x00':
            ps += new_byte
    return b'\x00\x02' + ps + b'\x00' + plaintext

def pkcsv15pad_sign(data, n):
    # pad data for signing according to PKCS#1 v1.5:
    # Format: 0x00 || 0x01 || PS (0xff) || 0x00 || T
    k = (n.bit_length() + 7) // 8
    if len(data) > k - 11:
        raise ValueError("Data too long for the given modulus")
    ps = b'\xff' * (k - len(data) - 3)
    return b'\x00\x01' + ps + b'\x00' + data

def pkcsv15pad_remove(padded):
    # removes PKCS#1 v1.5 padding (for encryption); expects 0x00 0x02 header
    if len(padded) < 11 or padded[0:2] != b'\x00\x02':
        raise ValueError("Invalid encryption padding")
    sep = padded.find(b'\x00', 2)
    if sep < 0 or sep < 10:
        raise ValueError("Invalid encryption padding")
    return padded[sep+1:]

def pkcsv15_unpad_sign(signed):
    # removes PKCS#1 v1.5 padding from signature; expects 0x00 0x01 header
    if len(signed) < 11 or signed[0:2] != b'\x00\x01':
        raise ValueError("Invalid signature padding")
    sep = signed.find(b'\x00', 2)
    if sep < 0:
        raise ValueError("Invalid signature padding")
    return signed[sep+1:]

def encrypt(keyfile, plaintextfile, ciphertextfile):
    n, e = get_pubkey(keyfile)
    k = (n.bit_length() + 7) // 8
    with open(plaintextfile, 'rb') as f:
        plaintext = f.read()
    padded = pkcsv15pad_encrypt(plaintext, n)
    m_int = bi(padded)
    c_int = pow(m_int, e, n)
    ciphertext = ib(c_int, k)
    with open(ciphertextfile, 'wb') as f:
        f.write(ciphertext)

def decrypt(keyfile, ciphertextfile, plaintextfile):
    n, d = get_privkey(keyfile)
    k = (n.bit_length() + 7) // 8
    with open(ciphertextfile, 'rb') as f:
        ciphertext = f.read()
    c_int = bi(ciphertext)
    m_int = pow(c_int, d, n)
    padded = ib(m_int, k)
    plaintext = pkcsv15pad_remove(padded)
    with open(plaintextfile, 'wb') as f:
        f.write(plaintext)

def digestinfo_der(filename):
    # returns DER-encoded DigestInfo structure for the SHA-256 digest of the file
    with open(filename, 'rb') as f:
        data = f.read()
    digest = hashlib.sha256(data).digest()
    # Build AlgorithmIdentifier: SEQUENCE { OID, NULL }
    alg_oid = encode_oid("2.16.840.1.101.3.4.2.1")
    alg_id = encode_sequence(alg_oid, encode_null())
    digest_oct = encode_octetstring(digest)
    return encode_sequence(alg_id, digest_oct)

def sign(keyfile, filetosign, signaturefile):
    n, d = get_privkey(keyfile)
    k = (n.bit_length() + 7) // 8
    di = digestinfo_der(filetosign)
    padded = pkcsv15pad_sign(di, n)
    s_int = pow(bi(padded), d, n)
    signature = ib(s_int, k)
    with open(signaturefile, 'wb') as f:
        f.write(signature)

def verify(keyfile, signaturefile, filetoverify):
    n, e = get_pubkey(keyfile)
    k = (n.bit_length() + 7) // 8
    with open(signaturefile, 'rb') as f:
        signature = f.read()
    s_int = bi(signature)
    m_int = pow(s_int, e, n)
    recovered = ib(m_int, k)
    try:
        unpadded = pkcsv15_unpad_sign(recovered)
    except Exception:
        print("Verification failure")
        return
    expected = digestinfo_der(filetoverify)
    if unpadded == expected:
        print("Verified OK")
    else:
        print("Verification failure")

def usage():
    print("Usage:")
    print("encrypt <public key file> <plaintext file> <output ciphertext file>")
    print("decrypt <private key file> <ciphertext file> <output plaintext file>")
    print("sign <private key file> <file to sign> <signature output file>")
    print("verify <public key file> <signature file> <file to verify>")
    sys.exit(1)

if len(sys.argv) != 5:
    usage()
elif sys.argv[1] == 'encrypt':
    encrypt(sys.argv[2], sys.argv[3], sys.argv[4])
elif sys.argv[1] == 'decrypt':
    decrypt(sys.argv[2], sys.argv[3], sys.argv[4])
elif sys.argv[1] == 'sign':
    sign(sys.argv[2], sys.argv[3], sys.argv[4])
elif sys.argv[1] == 'verify':
    verify(sys.argv[2], sys.argv[3], sys.argv[4])
else:
    usage()
