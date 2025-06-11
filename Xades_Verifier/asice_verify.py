#!/usr/bin/env python3

# do not use any other imports/libraries
import codecs
import datetime
import hashlib
import io
import sys
import zipfile

# apt-get install python3-bs4 python3-pyasn1-modules python3-m2crypto python3-lxml
from M2Crypto import X509, EC
import lxml.etree
from bs4 import BeautifulSoup
from pyasn1.codec.der import decoder, encoder
from pyasn1_modules import rfc2560

def verify_ecdsa(cert, signature_value, signed_hash):
    # verifies ECDSA signature given the hash value
    x509 = X509.load_cert_der_string(cert)
    EC_pubkey = EC.pub_key_from_der(x509.get_pubkey().as_der())

    # constructing r and s to satisfy M2Crypto
    l = len(signature_value)//2
    r = signature_value[:l]
    s = signature_value[l:]
    if r[0]>>7:
        r = b'\x00' + r
    if s[0]>>7:
        s = b'\x00' + s
    r = b'\x00\x00\x00' + bytes([len(r)]) + r
    s = b'\x00\x00\x00' + bytes([len(s)]) + s
    return EC_pubkey.verify_dsa(signed_hash, r, s)

def parse_tsa_response(timestamp_resp):
    # extracts from a TSA response the timestamp and timestamped DigestInfo
    timestamp = decoder.decode(timestamp_resp)
    tsinfo = decoder.decode(timestamp[0][1][2][1])[0]
    ts_digestinfo = encoder.encode(tsinfo[2])
    ts = datetime.datetime.strptime(str(tsinfo[4]), '%Y%m%d%H%M%SZ')
    # let's assume that the timestamp has been issued by a trusted TSA
    return ts, ts_digestinfo

def parse_ocsp_response(ocsp_resp):
    # extracts from an OCSP response certID_serial, certStatus and thisUpdate
    ocspResponse, _ = decoder.decode(ocsp_resp, asn1Spec=rfc2560.OCSPResponse())
    responseStatus = ocspResponse.getComponentByName('responseStatus')
    assert responseStatus == rfc2560.OCSPResponseStatus('successful'), responseStatus.prettyPrint()
    responseBytes = ocspResponse.getComponentByName('responseBytes')
    responseType = responseBytes.getComponentByName('responseType')
    assert responseType == rfc2560.id_pkix_ocsp_basic, responseType.prettyPrint()
    response = responseBytes.getComponentByName('response')
    basicOCSPResponse, _ = decoder.decode(response, asn1Spec=rfc2560.BasicOCSPResponse())
    tbsResponseData = basicOCSPResponse.getComponentByName('tbsResponseData')
    response0 = tbsResponseData.getComponentByName('responses').getComponentByPosition(0)
    # let's assume that the OCSP response has been signed by a trusted OCSP responder
    certID = response0.getComponentByName('certID')
    # let's assume that the issuer name and key hashes in certID are correct
    certID_serial = certID[3]
    certStatus = response0.getComponentByName('certStatus').getName()
    thisUpdate = datetime.datetime.strptime(str(response0.getComponentByName('thisUpdate')), '%Y%m%d%H%M%SZ')

    return certID_serial, certStatus, thisUpdate

def canonicalize(full_xml, tagname):
    # returns XML canonicalization of an element with the specified tagname
    if type(full_xml)!=bytes:
        print("[-] canonicalize(): input is not a bytes object containing XML:", type(full_xml))
        exit(1)
    input = io.BytesIO(full_xml)
    et = lxml.etree.parse(input)
    output = io.BytesIO()
    lxml.etree.ElementTree(et.find('.//{*}'+tagname)).write_c14n(output)
    return output.getvalue()

def get_subject_cn(cert_der):
    # returns CommonName value from the certificate's Subject Distinguished Name field
    # looping over Distinguished Name entries until CN found
    for rdn in decoder.decode(cert_der)[0][0][5]:
        if str(rdn[0][0]) == '2.5.4.3': # CommonName
            return str(rdn[0][1])
    return ''


filename = sys.argv[1]

#open the ZIP and read XML 
archive = zipfile.ZipFile(filename, 'r')
xmldoc = archive.read('META-INF/signatures0.xml')
soup = BeautifulSoup(xmldoc, 'xml')

#the file name referenced
reference = soup.find('Reference')
file_name = reference['URI']

#read the file data
file_data = archive.read(file_name)
print(f"[+] Signed file: {file_name}")

# TEST 1
file_ref = soup.find('Reference', {'URI': file_name})
expected_digest = file_ref.find('DigestValue').text.strip()
file_hash = hashlib.sha256(file_data).digest()
actual_digest = codecs.encode(file_hash, 'base64').decode().replace('\n', '').strip()

# forgery 2 error
if expected_digest != actual_digest:
    print("[-] The file hash does not match.")
    sys.exit(1)

# let's trust this certificate
cert_b64 = soup.find('X509Certificate').text.strip()
signers_cert_der = codecs.decode(cert_b64.encode(), 'base64')
print("[+] Signatory:", get_subject_cn(signers_cert_der))

# TEST 2
cert_digest_expected_b64 = soup.find('xades:CertDigest').find('ds:DigestValue').text.strip()
cert_digest_expected = codecs.decode(cert_digest_expected_b64.encode(), 'base64')
cert_digest_actual = hashlib.sha256(signers_cert_der).digest()

# Forgery 1 error
if cert_digest_expected != cert_digest_actual:
    print("[-] The certificate hash does not match.")
    sys.exit(1)

#extract the timestamp from the signature
timestamp_b64 = soup.find('EncapsulatedTimeStamp').text.strip()
timestamp_resp = codecs.decode(timestamp_b64.encode(), 'base64')
ts, ts_digestinfo = parse_tsa_response(timestamp_resp)
print("[+] Timestamped: %s +00:00" % (ts))

# Forgery 5 error
signature_value_str = canonicalize(xmldoc, "SignatureValue")
digest = hashlib.sha256(signature_value_str).digest()
digestinfo_sha256_prefix = codecs.decode(b'3031300d060960864801650304020105000420', 'hex')
signed_info_digestinfo = digestinfo_sha256_prefix + digest

if signed_info_digestinfo != ts_digestinfo:
    print("[-] The timestamp does not cover the correct <SignatureValue>!")
    sys.exit(1)

#decode the signature
signature_value_b64 = soup.find("SignatureValue").text.strip()
signature_value = codecs.decode(signature_value_b64.encode(), 'base64')

digest_algo = hashlib.sha384
signed_info_str = canonicalize(xmldoc, "SignedInfo")
sig_digest = digest_algo(signed_info_str).digest()

# Forgery 3/4 error on DigestValue
if verify_ecdsa(signers_cert_der, signature_value, sig_digest):
    print("[+] Signature verification successful!")
else:
    print("[-] Signature verification failure!")