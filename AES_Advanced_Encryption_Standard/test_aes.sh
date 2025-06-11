#!/bin/bash

echo '$ echo -n "hello world" > plain'
echo -n "hello world" > plain
echo '$ ./aes.py -encrypt plain plain.enc'
./aes.py -encrypt plain plain.enc
rm -f plain.new
echo '$ ./aes.py -decrypt plain.enc plain.new'
./aes.py -decrypt plain.enc plain.new
echo '$ hexdump -C plain.new'
hexdump -C plain.new
echo

echo '$ echo -e -n "hello world \x01\x01\x02\x02" > plain'
echo -e -n "hello world \x01\x01\x02\x02" > plain
echo '$ ./aes.py -encrypt plain plain.enc'
./aes.py -encrypt plain plain.enc
rm -f plain.new
echo '$ ./aes.py -decrypt plain.enc plain.new'
./aes.py -decrypt plain.enc plain.new
echo '$ hexdump -C plain.new'
hexdump -C plain.new
echo

echo '$ echo -e -n "0123456789123456hello world \x01\x01\x02\x02" > plain'
echo -e -n "0123456789123456hello world \x01\x01\x02\x02" > plain
echo '$ ./aes.py -encrypt plain plain.enc'
./aes.py -encrypt plain plain.enc
rm -f plain.new
echo '$ ./aes.py -decrypt plain.enc plain.new'
./aes.py -decrypt plain.enc plain.new
echo '$ hexdump -C plain.new'
hexdump -C plain.new
echo


