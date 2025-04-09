#!/bin/bash

# must be executed before:
#openssl genpkey -algorithm RSA -out priv_subject.pem -pkeyopt rsa_keygen_bits:2048
#openssl req -new -key priv_subject.pem -out example.com.csr

rm -f issued.pem

echo '$ ./issue_cert.py CA_cert.pem CA_priv.pem example.com.csr issued.pem'
./issue_cert.py CA_cert.pem CA_priv.pem example.com.csr issued.pem
echo
read

echo '$ openssl verify -CAfile CA_cert.pem -purpose sslserver issued.pem'
openssl verify -CAfile CA_cert.pem -purpose sslserver issued.pem
echo
read

echo '$ openssl verify -CAfile CA_cert.pem -purpose smimesign issued.pem'
openssl verify -CAfile CA_cert.pem -purpose smimesign issued.pem
echo
read

echo '$ openssl x509 -in issued.pem -text'
openssl x509 -in issued.pem -text
