# Elliptic Curve Crypto for Apple standards

## Motivation

There is currently no Javascript implementation of ECIES compatible
with apple's SecKeyAlgorithm standards. This library is an attempt to solve this problem ! Please refer to the original package for docs [eccrypto](https://github.com/bitchan/eccrypto.git). Everything is the same except that in ECIES, this library uses :

- The secp256r1 curve (or: prime256v1) for its operations
- A simple ANSII X9.63 SHA-256 KDF implemenation
- A variable 16 Bytes IV derived from the second half of the KDF
- AES-GCM with 128 bits key derived from the first half of the KDF
- HMAC is removed as it is not needed with AES-GCM

These changes make the encrypted bytes compatible with Apple's **SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA256AESGCM**

Credits to [David Schuetz](https://darthnull.org/security/2018/05/31/secure-enclave-ecies/) for figuring out some of the inner workings of Apple's implementation.

## License

eccrypto - JavaScript Elliptic curve cryptography library

Written in 2014-2015 by Kagami Hiiragi <kagami@genshiken.org>

To the extent possible under law, the author(s) have dedicated all copyright and related and neighboring rights to this software to the public domain worldwide. This software is distributed without any warranty.

You should have received a copy of the CC0 Public Domain Dedication along with this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
