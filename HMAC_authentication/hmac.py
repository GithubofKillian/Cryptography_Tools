#!/usr/bin/env python3 
import codecs, hashlib, sys
from pyasn1.codec.der import decoder
sys.path = sys.path[1:] # don't remove! otherwise the library import below will try to import your hmac.py
import hmac 

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

def mac(filename):
    # Initialisation
    key = input("[?] Enter key: ").encode()
    object_HMAC_SHA256 = hmac.new(key, digestmod=hashlib.sha256)
    file_open = open(filename, 'rb')

    # Add text to the HMAC_object
    while part := file_open.read(512):
        object_HMAC_SHA256.update(part)

    # Hash Text creation
    digest_text = object_HMAC_SHA256.digest()
    print("[+] Calculated HMAC-SHA256:", digest_text.hex())

    # Create the DigestInfo structure (ASN.1 format)
    digest_algorithm = asn1_objectidentifier([1, 2, 840, 113549, 2, 9])  # Object identifier for SHA-256 (OID for SHA-256: 1.2.840.113549.2.9)
    digest_info = asn1_sequence(digest_algorithm + asn1_octetstring(digest_text))

    # Create a new file and write the DigestInfo
    with open(filename + ".hmac", 'wb') as newfilename:
        newfilename.write(digest_info)
    print("[+] Writing DigestInfo to", filename + ".hmac")


# Correspondances OID -> Algorithmes de hachage
hash_algorithms = {
    '1.2.840.113549.2.5': hashlib.md5,  # MD5
    '1.3.14.3.2.26': hashlib.sha1,     # SHA-1
    '1.2.840.113549.2.9': hashlib.sha256,  # SHA-256
}

def verify(filename):
    print("[+] Reading DigestInfo from", filename + ".hmac")
    
    # Lire le fichier .hmac contenant la structure ASN.1 DigestInfo
    with open(filename + ".hmac", 'rb') as Digest_filename:
        digest_data = Digest_filename.read()

    # Décoder la structure DigestInfo ASN.1
    try:
        decoded, _ = decoder.decode(digest_data)
    except Exception as e:
        print(f"[-] Error decoding DigestInfo: {e}")
        return

    # Extraire l'algorithme et le digest de la structure ASN.1
    digest_algorithm = decoded.getComponentByPosition(0)  # DigestAlgorithm
    digest = decoded.getComponentByPosition(1)  # Digest (HMAC)

    # Convertir l'OID de l'algorithme en une chaîne
    algorithm_oid = '.'.join(str(i) for i in digest_algorithm)

    # Vérifier si l'OID correspond à un algorithme supporté
    if algorithm_oid not in hash_algorithms:
        print(f"[-] Unsupported algorithm with OID: {algorithm_oid}")
        return
    
    # Demander la clé
    key = input("[?] Enter key: ").encode()

    # Sélectionner l'algorithme de hachage approprié
    hash_function = hash_algorithms[algorithm_oid]
    
    # Créer l'objet HMAC pour recalculer le digest
    object_HMAC = hmac.new(key, digestmod=hash_function)
    
    # Calculer le HMAC en utilisant le fichier
    with open(filename, 'rb') as file:
        while part := file.read(512):
            object_HMAC.update(part)

    digest_calculated = object_HMAC.digest()

    # Afficher le digest attendu sous forme hexadécimale
    print("[+] Expected digest:", digest.asOctets().hex()) 
    print("[+] Calculated HMAC:", digest_calculated.hex())

    if digest_calculated != digest:
        print("[-] Wrong key or message has been manipulated!")
    else:
        print("[+] HMAC verification successful!")

def usage():
    print("Usage:")
    print("-mac <filename>")
    print("-verify <filename>")
    sys.exit(1)

if len(sys.argv) != 3:
    usage()
elif sys.argv[1] == '-mac':
    mac(sys.argv[2])
elif sys.argv[1] == '-verify':
    verify(sys.argv[2])
else:
    usage()
