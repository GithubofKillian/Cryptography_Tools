#!/bin/bash
echo "key:testkey [MAC:a8be648dd48738b964391a00d4522fe988d10e3d5b2dbf8629a3dcbc0ce93ffd]"
echo '$ echo -e -n "\x01" > file'
echo -e -n "\x01" > file
echo '$ ./hmac.py -mac file'
./hmac.py -mac file

echo ""
echo '$ ./hmac.py -verify file'
./hmac.py -verify file

echo ""
echo "MD5 secretkey: [MAC:9e8031ab9d85a5fa0753344bc8c31a2f]"
echo '$ ./hmac.py -verify file_md5'
./hmac.py -verify file_md5

echo ""
echo "SHA1 secretkey: [MAC:ebfb4fc1a84d5f9fcbd1b7c8d5d625ac9f5b4c81]"
echo '$ ./hmac.py -verify file_sha1'
./hmac.py -verify file_sha1

echo ""
echo "SHA256 secrettkey: [MAC:c40932474350a3f29a9f800e68b6429c64b7526800f8701ae9b4e73db8a3b700]"
echo '$ ./hmac.py -verify file_sha256'
./hmac.py -verify file_sha256
