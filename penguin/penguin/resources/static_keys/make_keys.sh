#!/bin/bash

# We shim ssh-keygen to pull the ssh.* files instead of generating
# The others are for openssl shims
openssl genpkey -algorithm RSA -out ./rsa2048.pem -pkeyopt rsa_keygen_bits:2048
openssl genpkey -algorithm RSA -out ./rsa4096.pem -pkeyopt rsa_keygen_bits:4096

openssl dsaparam -out ./dsaparam.pem 2048
openssl gendsa -out ./dsa2048.pem ./dsaparam.pem

openssl ecparam -name prime256v1 -genkey -noout -out ./ecdsa_prime256v1.pem

