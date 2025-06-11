#!/usr/bin/env python3

import time, os, sys
from pyasn1.codec.der import decoder

# $ sudo apt-get install python3-pycryptodome
sys.path = sys.path[1:] # removes current directory from aes.py search path
from Cryptodome.Cipher import AES          # https://pycryptodome.readthedocs.io/en/latest/src/cipher/classic.html#ecb-mode
from Cryptodome.Util.strxor import strxor  # https://pycryptodome.readthedocs.io/en/latest/src/util/util.html#crypto-util-strxor-module
from hashlib import pbkdf2_hmac
import hashlib, hmac


#==== ASN1 encoder start ====
# put DER encoder functions here
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

# this function benchmarks how many PBKDF2 iterations can be done
def benchmark():
    # measure time for performing 10000 iterations
    password = b"test"
    salt = os.urandom(8)
    iter_count = 10000
    start = time.time()
    pbkdf2_hmac('sha1', password, salt, iter_count, 48)
    stop = time.time()
    took = stop - start

    # extrapolate to 1 second
    iterations_per_second = iter_count / took
    target_iter = int(iterations_per_second)
    print("[+] Benchmark: %s PBKDF2 iterations in 1 second" % (target_iter))
    return target_iter

def encrypt(pfile, cfile):
    # benchmarking
    iter_count = benchmark()

    # asking for a password
    password = input("[?] Enter password: ").encode()

    # generate salt and iv
    salt = os.urandom(8)
    iv = os.urandom(16)

    # derieving keys
    key = pbkdf2_hmac('sha1', password, salt, iter_count, 48)

    # reading plaintext
    with open(pfile, 'rb') as f:
        contents = f.read()

    # padding plaintext
    size = 16
    padding_length = size - len(contents) % size
    contents += bytes([padding_length]) * padding_length

    # Extract the first 16 bytes for AES-128 and the next 32 bytes for HMAC-SHA256
    aes_key = key[:16]
    hmac_key = key[16:]
    
    # encrypting padded plaintext
    cipher = AES.new(aes_key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(contents)

    # MAC calculation (iv+ciphertext)
    mac = hmac.new(hmac_key, bytes(iv) + bytes(ciphertext), hashlib.sha256).digest()

    # constructing DER header
    asn1_header = asn1_sequence(
        asn1_objectidentifier([2, 16, 840, 1, 101, 3, 4, 2, 1])
        + asn1_octetstring(salt)
        + asn1_octetstring(iv)
        + asn1_octetstring(mac)
        + asn1_integer(iter_count)
    )

    # writing DER header and ciphertext to file
    header_length = len(asn1_header)
    with open(cfile, 'wb') as f:
        f.write(header_length.to_bytes(4, 'big'))
        f.write(asn1_header)
        f.write(ciphertext)

def decrypt(cfile, pfile):
    # reading DER header and ciphertext
    with open(cfile, 'rb') as f:
        header_length = int.from_bytes(f.read(4), 'big')
        header_bytes = f.read(header_length)
        ciphertext = f.read()
    decoded, _ = decoder.decode(header_bytes)
   
    # asking for a password
    password = input("[?] Enter password: ").encode()
    
    # Extraction
    salt = decoded.getComponentByPosition(1).asOctets()
    iv = decoded.getComponentByPosition(2).asOctets()
    expected_mac = decoded.getComponentByPosition(3).asOctets()
    stored_iter = int(decoded.getComponentByPosition(4))
    
    # derieving keys
    key = pbkdf2_hmac('sha1', password, salt, stored_iter, 48)

    # Extraction
    aes_key = key[:16]
    hmac_key = key[16:]
    
    # before decryption checking MAC (iv+ciphertext)
    mac = hmac.new(hmac_key, iv + ciphertext, hashlib.sha256).digest()
    if mac != expected_mac:
        print("[-] Integrity check failed!")
        return
    
    # decrypting ciphertext
    cipher = AES.new(aes_key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)
    
    # removing padding and writing plaintext to file
    padding_length = plaintext[-1]
    plaintext = plaintext[:-padding_length]
    with open(pfile, 'wb') as f:
        f.write(plaintext)

def usage():
    print("Usage:")
    print("-encrypt <plaintextfile> <ciphertextfile>")
    print("-decrypt <ciphertextfile> <plaintextfile>")
    sys.exit(1)

if len(sys.argv) != 4:
    usage()
elif sys.argv[1] == '-encrypt':
    encrypt(sys.argv[2], sys.argv[3])
elif sys.argv[1] == '-decrypt':
    decrypt(sys.argv[2], sys.argv[3])
else:
    usage()
