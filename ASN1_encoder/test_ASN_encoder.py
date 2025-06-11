#!/usr/bin/env python3
import sys, os, hashlib, traceback, codecs

### must be executed from the directory where asn1_encoder.py resides

error = {}
grade = False
if len(sys.argv) > 2: grade = True
asn1name = "/tmp/asn1.der.produced"

try:
    os.remove(asn1name)
except:
    pass


dername = "/tmp/asn1.der.expected"

# write DER structure that we expect to obtain
der = """
a07230703110020105a204020200c8ab05020300ff7f0101ff0302056004
330001020202020202020202020202020202020202020202020202020202
02020202020202020202020202020202020202020202050006072a864886
f70d010c0668656c6c6f2e170d3235303232333031303930305a
"""
open(dername, 'wb').write(codecs.decode(der.replace("\n",""), 'hex'))
sys.argv = ["", asn1name]
from asn1_encoder import *

# check if output DER created
if not os.path.isfile(asn1name):
    print("[-] No output DER produced!")
    error['output'] = {'success':0, 'error':2}
else:
    # check if matches expected
    digest_produced = hashlib.sha1(open(asn1name, 'rb').read()).digest().hex()
    digest_expected = hashlib.sha1(open(dername, 'rb').read()).digest().hex()
    if digest_produced != digest_expected:
        print("[-] Produced DER file does not match expected!")
        os.system("dumpasn1 " + dername + " > /tmp/der.expect")
        os.system("dumpasn1 " + asn1name + " > /tmp/der.produced")
        os.system("diff -u /tmp/der.expect /tmp/der.produced")
        error['output'] = {'success':1, 'error':1}
    else:
        error['output'] = {'success':2, 'error':0}


def test_der(fname, args, expected):
    global error

    if fname not in error: error[fname] = {'success':0, 'error':0}

    try:
        der = globals()[fname](*args)
        derhex = codecs.encode(der, 'hex')
        if derhex != expected:
            print("[-] %s(%s): Expected '%s' got '%s'" % (fname, repr(args)[:40], expected.decode(), derhex.decode()))
            error[fname]['error'] += 1
        else:
            error[fname]['success'] += 1
        return der
    except:
        print("[-] Failed to execute: %s(%s)" % (fname, repr(args)[:40]))
        print(traceback.format_exc())
        error[fname]['error'] += 1

def print_grade():
    global error
    points = {
	'asn1_len':1,
	'asn1_boolean':0,
	'asn1_octetstring':0.2,
	'asn1_null':0.2,
	'asn1_sequence':0.2,
	'asn1_set':0.2,
	'asn1_utf8string':0.2,
	'asn1_utctime':0.2,
	'asn1_tag_explicit':0.3,
	'asn1_integer':0.5,
	'asn1_objectidentifier':2,
	'asn1_bitstring':1.5,
	'output':0.5,
    }

    total = sum([points[test] for test in points])
    print("Total: %sp" % (total))
    obtained = 0
    partial = False
    for test in points:
        if error[test]['error']==0:
            print("[+] PASS %s(): -- %sp" % (test, points[test]))
            obtained+= points[test]
        elif error[test]['success'] > 0:
            print("[?] PARTIAL %s(): -- %s tests out of %s succeeded! (X out of %s points)" % (test, error[test]['success'], error[test]['success']+error[test]['error'], points[test]))
            partial = True
        else:
            print("[-] FAILED %s(): -- 0p out of %sp" % (test, points[test]))
    print("[+] Got %s points! Check PARTIAL and FAILED for manual grading." % (obtained))


test_der("asn1_len", [b""], b"00")
test_der("asn1_len", [b"1"], b"01")
test_der("asn1_len", [b"   126"*21], b"7e")
test_der("asn1_len", [b"   127"*21+b" "], b"7f")
test_der("asn1_len", [b" 128"*32], b"8180")
test_der("asn1_len", [b"     65540"*6554], b"83010004")

test_der("asn1_boolean", [True], b"0101ff")
test_der("asn1_boolean", [False], b"010100")
test_der("asn1_octetstring", [b"\x00hohoho"], b"040700686f686f686f")
test_der("asn1_octetstring", [b"\xff"*550], b"04820226"+b"ff"*550)
test_der("asn1_null", [], b"0500")
test_der("asn1_sequence", [asn1_null()], b"30020500")
test_der("asn1_sequence", [b"\x13\x82\x01\xc2"+b"abc"*150], b"308201c6"+b"138201c2"+b"616263"*150)
test_der("asn1_set", [asn1_null()], b"31020500")
test_der("asn1_set", [b"\x13\x82\x01\xc2"+b"abc"*150], b"318201c6"+b"138201c2"+b"616263"*150)
test_der("asn1_utf8string", [b"foo"], b"0c03666f6f")
test_der("asn1_utf8string", [b"abc"*150], b"0c8201c2"+b"616263"*150)
test_der("asn1_utctime", [b"120929010100Z"], b"170d3132303932393031303130305a")
test_der("asn1_tag_explicit", [asn1_null(), 0], b"a0020500")
test_der("asn1_tag_explicit", [asn1_null(), 4], b"a4020500")
test_der("asn1_tag_explicit", [asn1_null(), 30], b"be020500")
test_der("asn1_tag_explicit", [b"\x13\x82\x01\xc2"+b"abc"*150, 30], b"be8201c6"+b"138201c2"+b"616263"*150)
test_der("asn1_integer", [0], b"020100")
test_der("asn1_integer", [1], b"020101")
test_der("asn1_integer", [127], b"02017f")
test_der("asn1_integer", [128], b"02020080")
test_der("asn1_integer", [255], b"020200ff")
test_der("asn1_integer", [256], b"02020100")
test_der("asn1_integer", [65537], b"0203010001")
test_der("asn1_integer", [32767], b"02027fff")
test_der("asn1_integer", [32768], b"0203008000")
test_der("asn1_integer", [12345 << 1234 ], b"02819d00c0e4"+b"00"*154)
#test_der("asn1_integer", [-1], "0201ff")
#test_der("asn1_integer", [-2], "0201fe")
#test_der("asn1_integer", [-128], "020180")
#test_der("asn1_integer", [-129], "0202ff7f")
#test_der("asn1_integer", [-130], "0202ff7e")
#test_der("asn1_integer", [-1000000], "0203f0bdc0")
test_der("asn1_objectidentifier", [[1,2]], b"06012a")
test_der("asn1_objectidentifier", [[1,2,840]], b"06032a8648")
test_der("asn1_objectidentifier", [[1,2,840,5,1000000]], b"06072a864805bd8440")
test_der("asn1_objectidentifier", [[1,2,840,5,127,128,129]], b"06092a8648057f81008101")
test_der("asn1_objectidentifier", [[1,2,840,5,127,128,129]+[100000000]*50], b"0681d12a8648057f81008101"+b"afd7c200"*50)
test_der("asn1_bitstring", [""], b"030100")
test_der("asn1_bitstring", ["0"], b"03020700")
test_der("asn1_bitstring", ["1"], b"03020780")
test_der("asn1_bitstring", ["101010"], b"030202a8")
test_der("asn1_bitstring", ["0011111111"], b"0303063fc0")
test_der("asn1_bitstring", ["0011111111000000"], b"0303003fc0")
test_der("asn1_bitstring", ["00000000001111"], b"030302003c")
test_der("asn1_bitstring", ["0000000000000000001111"], b"03040200003c")
test_der("asn1_bitstring", ["00000000"*150], b"03819700"+ b"00"*150)


failed = False
for test in error:
    if error[test]['error']:
        failed = True

if failed:
    print("[-] Some of the tests failed!")
else:
    print("[+] All tests succeeded!")

if grade:
    print_grade()
