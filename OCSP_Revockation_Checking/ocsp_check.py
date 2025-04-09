#!/usr/bin/env python3
# do not use any other imports/libraries
import codecs, datetime, hashlib, re, sys, socket
from urllib.parse import urlparse
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import namedtype, univ

# Took 8 hours
# sudo apt install python3-pyasn1-modules
from pyasn1_modules import rfc2560, rfc5280

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
    # converts PEM-encoded X.509 certificate (if it is in PEM) to DER
    if content[:2] == b'--':
        content = content.replace(b"-----BEGIN CERTIFICATE-----", b"")
        content = content.replace(b"-----END CERTIFICATE-----", b"")
        content = codecs.decode(content, 'base64')
    return content

def get_name(cert):
    # gets subject DN from certificate
    name_der = b''
    name = decoder.decode(cert)[0][0][5]  # subject field

    for rdn in name:  # each RDN is a SET of one or more attributeTypeAndValue
        rdn_der = b''
        for attr in rdn:  # usually just one
            oid = attr[0]
            value = attr[1]

            value_bytes = encoder.encode(value)
            oid_bytes = asn1_objectidentifier([int(i) for i in str(oid).split('.')])

            attr_der = asn1_sequence(oid_bytes + value_bytes)
            rdn_der += asn1_set(attr_der)

        name_der += rdn_der

    return name_der

def get_key(cert):
    # gets subjectPublicKey from certificate
    spki = decoder.decode(cert)[0][0][6]  # SubjectPublicKeyInfo
    public_key_bits = spki[1]  # BIT STRING
    return bytes(public_key_bits)[1:]  # skip the first byte (padding bits count)

def get_serial(cert):
    # gets serial from certificate
    return decoder.decode(cert)[0][0][1]

def produce_request(cert, issuer_cert):
    # makes OCSP request in ASN.1 DER form

    # construct CertID (use SHA1)
    issuer_name = get_name(issuer_cert)
    issuer_key = get_key(issuer_cert)
    serial = get_serial(cert)

    print("[+] OCSP request for serial:", serial)

    issuer_name_hash = hashlib.sha1(issuer_name).digest()
    issuer_key_hash = hashlib.sha1(issuer_key).digest()

    hash_algo = asn1_sequence(
        asn1_objectidentifier([1, 3, 14, 3, 2, 26]) +  # SHA1 OID
        asn1_null()
    )

    cert_id = asn1_sequence(
        hash_algo +
        asn1_octetstring(issuer_name_hash) +
        asn1_octetstring(issuer_key_hash) +
        asn1_integer(serial)
    )

    request = asn1_sequence(cert_id)
    request_list = asn1_sequence(request)

    # RequestorName = [1] EXPLICIT GeneralName (directoryName = [4] Name)
    directory_name = asn1_tag_explicit(issuer_name, 4)       # [4] directoryName
    requestor_name = asn1_tag_explicit(directory_name, 1)    # [1] requestorName

    # Assemble TBSRequest
    tbs_request = asn1_sequence(
        asn1_integer(0) +  # version
        requestor_name +
        request_list
    )

    # Final OCSPRequest
    ocsp_request = asn1_sequence(tbs_request)

    return ocsp_request

def send_req(ocsp_req, ocsp_url):
    # sends OCSP request to OCSP responder

    # parse OCSP responder's url
    url = urlparse(ocsp_url)
    host = url.netloc
    path = url.path if url.path else "/"

    print("[+] Connecting to %s..." % (host))
    # connect to host
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, 80))  # Connexion sur le port HTTP par défaut

    # send HTTP POST request
    request = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/ocsp-request\r\n"
        f"Content-Length: {len(ocsp_req)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode('utf-8') + ocsp_req

    # Print the request for debugging
    print("[+] Sending OCSP request:", request)

    s.send(request)

    # read HTTP response header
    response_header = b""
    while b"\r\n\r\n" not in response_header:
        chunk = s.recv(1024)
        if not chunk:
            break
        response_header += chunk

    # Split the header and body if the body is received in the same chunk
    header, body = response_header.split(b"\r\n\r\n", 1)

    # get HTTP response length
    match = re.search(b"content-length:\s*(\d+)", header, re.I)
    content_length = int(match.group(1)) if match else 0
    print(f"[+] Response length: {content_length} bytes")

    # read the remaining HTTP response body if necessary
    while len(body) < content_length:
        chunk = s.recv(min(1024, content_length - len(body)))
        if not chunk:
            break
        body += chunk

    ocsp_resp = body
    s.close()

    # Print the raw response for debugging
    print("[+] Raw response:", ocsp_resp)
    return ocsp_resp

def get_ocsp_url(cert):
    # gets the OCSP responder's url from the certificate's AIA extension
    # pyasn1 syntax description to decode AIA extension
    class AccessDescription(univ.Sequence):
        componentType = namedtype.NamedTypes(
            namedtype.NamedType('accessMethod', univ.ObjectIdentifier()),
            namedtype.NamedType('accessLocation', rfc5280.GeneralName())
        )

    class AuthorityInfoAccessSyntax(univ.SequenceOf):
        componentType = AccessDescription()

    # looping over certificate extensions
    for seq in decoder.decode(cert)[0][0][7]:
        if str(seq[0]) == '1.3.6.1.5.5.7.1.1':  # look for AIA extension
            ext_value = bytes(seq[1])
            for aia in decoder.decode(ext_value, asn1Spec=AuthorityInfoAccessSyntax())[0]:
                if str(aia[0]) == '1.3.6.1.5.5.7.48.1':  # ocsp url
                    return str(aia[1].getComponentByName('uniformResourceIdentifier'))

    print("[-] OCSP url not found in the certificate!")
    exit(1)

def get_issuer_cert_url(cert):
    # gets the CA's certificate URL from the certificate's AIA extension

    class AccessDescription(univ.Sequence):
        componentType = namedtype.NamedTypes(
            namedtype.NamedType('accessMethod', univ.ObjectIdentifier()),
            namedtype.NamedType('accessLocation', rfc5280.GeneralName())
        )

    class AuthorityInfoAccessSyntax(univ.SequenceOf):
        componentType = AccessDescription()

    # loop over extensions to find AIA
    for seq in decoder.decode(cert)[0][0][7]:
        if str(seq[0]) == '1.3.6.1.5.5.7.1.1':  # AIA extension
            ext_value = bytes(seq[1])
            for aia in decoder.decode(ext_value, asn1Spec=AuthorityInfoAccessSyntax())[0]:
                if str(aia[0]) == '1.3.6.1.5.5.7.48.2':  # CA Issuers OID
                    return str(aia[1].getComponentByName('uniformResourceIdentifier'))

    print("[-] Issuer certificate URL not found in the certificate!")
    exit(1)

def download_issuer_cert(issuer_cert_url):
    print("[+] Downloading issuer certificate from:", issuer_cert_url)

    # Step 1: Parse the URL to extract host and path
    url = urlparse(issuer_cert_url)
    host = url.netloc
    path = url.path

    # Step 2: Open a TCP socket to the host on port 80 (HTTP)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, 80))

    # Step 3: Send a valid HTTP/1.1 GET request
    request = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    s.send(request.encode())

    # Step 4: Read and split HTTP headers
    response = b''
    while b'\r\n\r\n' not in response:
        response += s.recv(1)

    header, body = response.split(b'\r\n\r\n', 1)

    # Step 5: Extract Content-Length using regex
    match = re.search(b'content-length:\s*(\d+)\s', header, re.S | re.I)
    if not match:
        print("[-] Could not determine content length.")
        exit(1)

    content_length = int(match.group(1))

    # Step 6: Read the rest of the body based on Content-Length
    while len(body) < content_length:
        body += s.recv(4096)

    s.close()
    return body

def parse_ocsp_resp(ocsp_resp):
    # parses OCSP response

    ocspResponse, _ = decoder.decode(ocsp_resp, asn1Spec=rfc2560.OCSPResponse())
    responseStatus = ocspResponse.getComponentByName('responseStatus')

    if responseStatus != rfc2560.OCSPResponseStatus('successful'):
        print("[-] OCSP response status:", responseStatus.prettyPrint())
        return

    # Extract responseBytes from the OCSP response
    responseBytes = ocspResponse.getComponentByName('responseBytes')
    responseType = responseBytes.getComponentByName('responseType')

    # Assert the responseType is the OCSP basic response
    assert responseType == rfc2560.id_pkix_ocsp_basic, responseType.prettyPrint()

    # Extract the actual OCSP response data
    response = responseBytes.getComponentByName('response')

    # Decode the basic OCSP response
    basicOCSPResponse, _ = decoder.decode(
        response, asn1Spec=rfc2560.BasicOCSPResponse()
    )

    # Extract the TBS (To Be Signed) response data
    tbsResponseData = basicOCSPResponse.getComponentByName('tbsResponseData')

    # Extract the first response (there could be more in a real-world case)
    response0 = tbsResponseData.getComponentByName('responses').getComponentByPosition(0)

    # Parse the time stamps and certificate status
    producedAt = datetime.datetime.strptime(str(tbsResponseData.getComponentByName('producedAt')), '%Y%m%d%H%M%SZ')
    thisUpdate = datetime.datetime.strptime(str(response0.getComponentByName('thisUpdate')), '%Y%m%d%H%M%SZ')
    nextUpdate = datetime.datetime.strptime(str(response0.getComponentByName('nextUpdate')), '%Y%m%d%H%M%SZ')

    # Get certificate status
    certStatus = response0.getComponentByName('certStatus').getName()

    # Output the information
    print("[+] OCSP producedAt: %s +00:00" % producedAt)
    print("[+] OCSP thisUpdate: %s +00:00" % thisUpdate)
    print("[+] OCSP nextUpdate: %s +00:00" % nextUpdate)
    print("[+] OCSP status:", certStatus)


cert = pem_to_der(open(sys.argv[1], 'rb').read())

ocsp_url = get_ocsp_url(cert)
print("[+] URL of OCSP responder:", ocsp_url)

issuer_cert_url = get_issuer_cert_url(cert)
issuer_cert = download_issuer_cert(issuer_cert_url)

ocsp_req = produce_request(cert, issuer_cert)
ocsp_resp = send_req(ocsp_req, ocsp_url)
parse_ocsp_resp(ocsp_resp)
