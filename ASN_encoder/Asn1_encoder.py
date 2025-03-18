#!/usr/bin/env python3
import sys   

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

# Modification uniquement sur cette ligne :
asn1 = asn1_tag_explicit(asn1_sequence(asn1_set(asn1_integer(42)) + asn1_boolean(True) + asn1_bitstring("011") + asn1_octetstring(b"data")), 0)
open(sys.argv[1], 'wb').write(asn1)
