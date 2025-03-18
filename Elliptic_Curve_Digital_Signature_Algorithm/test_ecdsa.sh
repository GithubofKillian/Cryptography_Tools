#!/bin/bash

echo "[+] Generating EC key pair..."
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out priv.pem
openssl ec -in priv.pem -pubout -out pub.pem

echo "[+] Testing ECDSA signing..."
dd if=/dev/urandom of=filetosign bs=1M count=1 > /dev/null 2>&1
./ecdsa.py sign priv.pem filetosign signature
openssl dgst -sha384 -verify pub.pem -signature signature filetosign

echo "[+] Testing ECDSA verification..."
openssl dgst -sha384 -sign priv.pem -out signature filetosign
./ecdsa.py verify pub.pem signature filetosign

echo "[+] Testing ECDSA failed verification..."
openssl dgst -sha1 -sign priv.pem -out signature filetosign
./ecdsa.py verify pub.pem signature filetosign
