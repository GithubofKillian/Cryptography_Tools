#!/usr/bin/env python3
# do not use any other imports/libraries
import argparse, codecs, hashlib, os, sys  
from pyasn1.codec.der import decoder, encoder

parser = argparse.ArgumentParser(description='issue TLS server certificate based on CSR', add_help=False)
parser.add_argument("CA_cert_file", help="CA certificate (in PEM or DER form)")
parser.add_argument("CA_private_key_file", help="CA private key (in PEM or DER form)")
parser.add_argument("csr_file", help="CSR file (in PEM or DER form)")
parser.add_argument("output_cert_file", help="File to store certificate (in PEM form)")
args = parser.parse_args()

def ib(i, length=False):
    # converts integer to bytes
    b = b''
    if length is False:
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

#==== ASN1 encoder start ====
# put your DER encoder functions here
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

def asn1_boolean(boolean):
    boolean = b'\xff' if boolean else b'\x00'
    return bytes([0x01]) + asn1_len(boolean) + boolean

def asn1_null():
    return bytes([0x05] + [0x00])

def asn1_integer(i):
    if i == 0:
        return bytes([0x02, 0x01, 0x00])
    iByte = int_to_bytestring(i)
    #Verify if the first bit (MSB) is 1.
    if iByte[0] & 0x80:
        iByte = b'\x00' + iByte
    return bytes([0x02]) + asn1_len(iByte) + iByte

#supplementary method for asn1_integer and asn1_len
def int_to_bytestring(i):
    if i == 0:
        return b'\x00'
    byte_list = []
    while i > 0:
        byte_list.append(i & 0xFF) 
        i >>= 8
    byte_list.reverse()
    return bytes(byte_list)

def asn1_bitstring(bit_str):
    #if input empty
    if not bit_str:
        return bytes([0x03, 0x01, 0x00])
    #for the padding
    real_length = len(bit_str)
    padding_bit = (8 - (real_length % 8)) % 8
    bit_str += "0" * padding_bit  # Add padding bits
    #convert to byte with the octet pattern
    byte_value = int(bit_str, 2).to_bytes(len(bit_str) // 8, byteorder='big')
    return bytes([0x03]) + asn1_len(len(byte_value) + 1) + bytes([padding_bit]) + byte_value

def asn1_octetstring(octets_str):
    return bytes([0x04]) + asn1_len(octets_str) + octets_str

def asn1_objectidentifier(oid):
    # First octet by combining 2 first component
    first_byte = oid[0] * 40 + oid[1]
    result = bytes([first_byte])
    #base-128 encoding
    for comp in oid[2:]:
        parts = []
        n = comp
        if n == 0:
            parts.append(0)
        else:
            while n:
                parts.insert(0, n & 0x7F)
                n //= 128
        for i in range(len(parts) - 1):
            parts[i] |= 0x80
        result += bytes(parts)
    return bytes([0x06]) + asn1_len(result) + result

def asn1_sequence(der):
    return bytes([0x30]) + asn1_len(len(der)) + der

def asn1_set(der):
    return bytes([0x31]) + asn1_len(len(der)) + der

def asn1_utf8string(utf8bytes):
    return bytes([0x0c]) + asn1_len(len(utf8bytes)) + utf8bytes

def asn1_utctime(time):
    return bytes([0x17]) + asn1_len(len(time)) + time

def asn1_tag_explicit(der, tag):
    if not der: 
        raise ValueError("Empty object")
    tag_byte = 0xA0 | tag
    return bytes([tag_byte]) + asn1_len(len(der)) + der
#==== ASN1 encoder end ====
def pem_to_der(content):
    # converts PEM content (if it is PEM) to DER
    if content[:2] == b'--':
        content = content.replace(b"-----BEGIN CERTIFICATE REQUEST-----", b"")
        content = content.replace(b"-----END CERTIFICATE REQUEST-----", b"")
        content = content.replace(b"-----BEGIN CERTIFICATE-----", b"")
        content = content.replace(b"-----END CERTIFICATE-----", b"")
        content = content.replace(b"-----BEGIN PUBLIC KEY-----", b"")
        content = content.replace(b"-----END PUBLIC KEY-----", b"")
        content = content.replace(b"-----BEGIN PRIVATE KEY-----", b"")
        content = content.replace(b"-----END PRIVATE KEY-----", b"")
        content = codecs.decode(content, 'base64')
    return content

def get_privkey(filename):
     # reads RSA private key file and returns (n, d)
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

def pkcsv15pad_sign(digestinfo, n):
    # pads plaintext for signing according to PKCS#1 v1.5
    # calculate byte size of modulus n
    k = (n.bit_length() + 7) // 8 
    padding_length = k - len(digestinfo) - 3
    # plaintext must be at least 11 bytes smaller than modulus
    if padding_length < 8:
        raise ValueError("Padding length too small! Check key size or digest info.")
    # add padding bytes
    ps = b'\xff' * padding_length 
    return b'\x00\x01' + ps + b'\x00' + digestinfo 

def digestinfo_der(filename):
    # returns ASN.1 DER-encoded DigestInfo structure containing SHA256 digest of m
    with open(filename, 'rb') as f:
        data = f.read()
    digest = hashlib.sha256(data).digest()
    alg_oid = encode_oid("2.16.840.1.101.3.4.2.1")
    alg_id = encode_sequence(alg_oid, encode_null())
    digest_oct = encode_octetstring(digest)
    return encode_sequence(alg_id, digest_oct)

def sign(m, keyfile):
    # signs DigestInfo of message m
    n, d = get_privkey(keyfile)
    m_int = bi(m)
    sig_int = pow(m_int, d, n)
    return ib(sig_int, (n.bit_length() + 7) // 8)

def get_subject_cn(csr_der):
    # returns CommonName value from CSR's Distinguished Name field
    # looping over Distinguished Name entries until CN found
    csr, _ = decoder.decode(csr_der)
    subject = csr[0][1]
    for rdn in subject:
        for attr in rdn:
            if str(attr[0]) == '2.5.4.3': 
                return str(attr[1])
    return "Unknown"

def get_subjectPublicKeyInfo(csr_der):
    # returns DER-encoded subjectPublicKeyInfo from CSR
    csr, _ = decoder.decode(csr_der)
    return encoder.encode(csr[0][2]) 

def get_subjectName(cert_der):
    # returns DER-encoded subject name from CA certificate
    return encoder.encode(decoder.decode(cert_der)[0][0][5])

def issue_certificate(private_key_file, issuer, subject, pubkey):
    # receives CA private key filename, DER-encoded CA Distinguished Name, self-constructed DER-encoded subject's Distinguished Name and DER-encoded subjectPublicKeyInfo
    serial_number = 1
    validity_not_before = b'230105000000Z'
    validity_not_after = b'260105000000Z'

    # Certificate Fields
    tbs_cert = asn1_sequence(
        asn1_integer(serial_number) +
        asn1_sequence(asn1_objectidentifier((1, 2, 840, 113549, 1, 1, 11)) + asn1_null()) +  # Algorithm: sha256WithRSAEncryption
        issuer +
        asn1_sequence(asn1_utctime(validity_not_before) + asn1_utctime(validity_not_after)) +
        subject +
        pubkey
    )

    # Create the signature
    tbs_digest = hashlib.sha256(tbs_cert).digest()
    digestinfo = asn1_sequence(
        asn1_sequence(asn1_objectidentifier((2, 16, 840, 1, 101, 3, 4, 2, 1)) + asn1_null()) +
        asn1_octetstring(tbs_digest)
    )

    padded = pkcsv15pad_sign(digestinfo, get_privkey(private_key_file)[0])
    signature = sign(padded, private_key_file)

    # Final X.509 Certificate
    certificate = asn1_sequence(
        tbs_cert +
        asn1_sequence(asn1_objectidentifier((1, 2, 840, 113549, 1, 1, 11)) + asn1_null()) +
        asn1_bitstring(bin(int.from_bytes(signature, byteorder='big'))[2:])
    )

    # returns X.509v3 certificate in PEM format
    cert_pem = b'-----BEGIN CERTIFICATE-----\n' + codecs.encode(certificate, 'base64').replace(b'\n', b'\r\n') + b'-----END CERTIFICATE-----\n'
    return cert_pem

# obtain subject's CN from CSR
csr_der = pem_to_der(open(args.csr_file, 'rb').read())
subject_cn_text = get_subject_cn(csr_der)

print("[+] Issuing certificate for \"%s\"" % (subject_cn_text))

# obtain subjectPublicKeyInfo from CSR
pubkey = get_subjectPublicKeyInfo(csr_der)

subject_cn_text = get_subject_cn(csr_der)  # Récupère le CN depuis la CSR

# Constructeur DER du nom du sujet (DN) : 
# Modified or it does not work with ellipsis schemes asn1_sequence(...)
subject = asn1_sequence(
    asn1_set(
        asn1_sequence(
            asn1_objectidentifier((2, 5, 4, 3)) +  # OID pour CommonName (CN)
            asn1_utf8string(subject_cn_text.encode('utf-8'))  # Valeur de CN
        )
    )
)

# get subject name DN from CA certificate
CAcert = pem_to_der(open(args.CA_cert_file, 'rb').read())
CAsubject = get_subjectName(CAcert)

# issue certificate
cert_pem = issue_certificate(args.CA_private_key_file, CAsubject, subject, pubkey)
open(args.output_cert_file, 'wb').write(cert_pem)
