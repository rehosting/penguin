#!/bin/bash

# We shim ssh-keygen to pull the ssh.* files instead of generating
# The others are for openssl shims
openssl genpkey -algorithm RSA -out ./rsa2048.pem -pkeyopt rsa_keygen_bits:2048
openssl genpkey -algorithm RSA -out ./rsa4096.pem -pkeyopt rsa_keygen_bits:4096

# TODO: missing commands to generate openssl keys?
openssl req -new -x509 -days 3650 -key openssl_1024.key -out openssl_1024.pem
openssl req -new -x509 -days 3650 -key openssl_2048.key -out openssl_2048.pem
openssl req -new -x509 -days 3650 -key openssl_4096.key -out openssl_4096.pem

openssl dsaparam -out ./dsaparam.pem 2048
openssl gendsa -out ./dsa2048.pem ./dsaparam.pem

openssl ecparam -name prime256v1 -genkey -noout -out ./ecdsa_prime256v1.pem

