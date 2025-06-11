#!/usr/bin/env python3

import argparse, codecs, sys     # do not use any other imports/libraries
from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.CardConnection import CardConnection
from smartcard.util import toHexString

# took x.y hours (please specify here how much time your solution required)

# parse arguments
parser = argparse.ArgumentParser(description='Fetch certificates from ID card', add_help=False)
parser.add_argument('--cert', type=str, default=None, choices=['auth','sign'], help='Which certificate to fetch')
parser.add_argument("--out", required=True, type=str, help="File to store certificate (PEM)")
args = parser.parse_args()

# this will wait until a card is inserted in any reader
channel = CardRequest(timeout=100, cardType=AnyCardType()).waitforcard().connection
print("[+] Selected reader:", channel.getReader())

# using T=0 for compatibility and simplicity
try:
    channel.connect(CardConnection.T0_protocol)
except:
    # fallback to T=1 if the reader does not support T=0
    channel.connect(CardConnection.T1_protocol)

# detect and print the EstEID card platform
atr = channel.getATR()
if atr == [0x3B,0xFE,0x18,0x00,0x00,0x80,0x31,0xFE,0x45,0x45,0x73,0x74,0x45,0x49,0x44,0x20,0x76,0x65,0x72,0x20,0x31,0x2E,0x30,0xA8]:
    print("[+] EstEID v3.x on JavaCard")
elif atr == [0x3B,0xFA,0x18,0x00,0x00,0x80,0x31,0xFE,0x45,0xFE,0x65,0x49,0x44,0x20,0x2F,0x20,0x50,0x4B,0x49,0x03]:
    print("[+] EstEID v3.5 (10.2014) cold (eID)")
elif atr == [0x3B,0xDB,0x96,0x00,0x80,0xB1,0xFE,0x45,0x1F,0x83,0x00,0x12,0x23,0x3F,0x53,0x65,0x49,0x44,0x0F,0x90,0x00,0xF1]:
    print("[+] Estonian ID card (2018)")
else:
    print("[-] Unknown card:", toHexString(atr))
    sys.exit(1)

def send(apdu):
    data, sw1, sw2 = channel.transmit(apdu)

    # success
    if [sw1,sw2] == [0x90,0x00]:
        return data
    # (T=0) card signals how many bytes to read
    elif sw1 == 0x61:
        #print("[=] More data to read:", sw2)
        return send([0x00, 0xC0, 0x00, 0x00, sw2]) # GET RESPONSE of sw2 bytes
    # (T=0) card signals incorrect Le
    elif sw1 == 0x6C:
        #print("[=] Resending with Le:", sw2)
        return send(apdu[0:4] + [sw2]) # resend APDU with Le = sw2
    # probably error condition
    else:
        print("Error: %02x %02x, sending APDU: %s" % (sw1, sw2, toHexString(apdu)))
        sys.exit(1)

# reading from the card auth or sign certificate
print("[=] Retrieving %s certificate..." % (args.cert))
send([0x00, 0xA4, 0x04, 0x00, 0x10,
      0xA0, 0x00, 0x00, 0x00, 0x77, 0x01, 0x08, 0x00,
      0x07, 0x00, 0x00, 0xFE, 0x00, 0x00, 0x01, 0x00]) # SELECT EstEID AID

if args.cert == "auth":
    #auth cert (file3401)
    send([0x00, 0xA4, 0x01, 0x0C, 0x02, 0xAD, 0xF1]) #ADF1 
    send([0x00, 0xA4, 0x02, 0x0C, 0x02, 0x34, 0x01]) #MF/ADF1/3401 (authentication certificate)
elif args.cert == "sign":
    #sign cert (file 341F)
    send([0x00, 0xA4, 0x01, 0x0C, 0x02, 0xAD, 0xF2]) #ADF2 and not AFD2
    send([0x00, 0xA4, 0x02, 0x0C, 0x02, 0x34, 0x1F]) #MF/ADF2/341F (digital signature certificate)
else:
    print("[-] Unknown certificate type")
    sys.exit(1)


# read the first 10 bytes to parse ASN.1 length field and determine certificate length
tenBytes = send([0x00, 0xB0, 0x00, 0x00, 10]) # B0 Read, 10 lenght

if tenBytes[0] != 0x30: #Sequence BYTE
    print("[-] Not a valid Sequence TAg")
    sys.exit(1)

lenght = tenBytes[1]
if lenght < 0x80:
    certlen = lenght + 2 # Tag & Lenght
elif lenght == 0x81:
    certlen = tenBytes[2] + 3 # Tag, Lenght, 0x81
elif lenght == 0x82:
    certlen = (tenBytes[2] << 8 | tenBytes[3]) + 4 # Tag, Lenght(2), 0x82
else:
    print("[-] Too Long")
    sys.exit(1)

print("[+] Certificate size: %d bytes" % certlen)
# reading DER-encoded certificate from the smart card
cert = bytearray()
i = 0
while i < certlen:
    remaining = min(231, certlen - i)
    sb, wb = i >> 8, i & 0xFF # i >> 8,strong byte, i & 0xFF, weak byte
    chunk = send([0x00, 0xB0, sb, wb, remaining]) # B0 Read
    cert.extend(chunk)
    i += remaining

# save certificate in PEM format
open(args.out,"wb").write(b"-----BEGIN CERTIFICATE-----\n"+codecs.encode(cert, 'base64')+b"-----END CERTIFICATE-----\n")
print("[+] Certificate stored in", args.out)
