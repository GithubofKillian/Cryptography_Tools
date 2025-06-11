#!/bin/bash
echo "[+] Generating RSA key pair..."
KEYSIZE=`shuf -n1 -e 2048 2041`
openssl genpkey -algorithm RSA -out priv.pem -pkeyopt rsa_keygen_bits:$KEYSIZE
openssl rsa -in priv.pem -pubout -out pub.pem

echo "[+] Testing encryption ($KEYSIZE-bit RSA)..."
echo "hello" > plain.txt
./rsa.py encrypt pub.pem plain.txt plain.enc
#ls -alh plain.enc
openssl pkeyutl -decrypt -inkey priv.pem -in plain.enc -out plain.dec
diff -u plain.txt plain.dec
#hexdump -C plain.txt
#hexdump -C plain.dec

# To see why openssl failed to decrypt the ciphertext do raw decryption with private key
# (the result should be correctly padded plaintext):
#openssl pkeyutl -inkey priv.pem -in plain.enc -decrypt -pkeyopt rsa_padding_mode:none -hexdump
#exit

echo "[+] Testing decryption (PEM)..."
openssl pkeyutl -encrypt -pubin -inkey pub.pem -in plain.txt -out plain.enc
rm -f plain.dec
./rsa.py decrypt priv.pem plain.enc plain.dec
diff -u plain.txt plain.dec

echo "[+] Testing decryption (DER)..."
openssl pkcs8 -nocrypt -inform pem -in priv.pem -topk8 -outform der -out priv.key
rm -f plain.dec
./rsa.py decrypt priv.key plain.enc plain.dec
diff -u plain.txt plain.dec

echo "[+] Testing signing..."
dd if=/dev/urandom of=filetosign bs=1M count=1 > /dev/null 2>&1
./rsa.py sign priv.pem filetosign signature
openssl dgst -sha256 -verify pub.pem -signature signature filetosign
