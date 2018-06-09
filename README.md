
# voting-booth #

This is a secure voting booth that uses encryption and digital signatures to ensure confidentiality and authentication, respectively. It was my submission for an assignment in CS 458: Introduction to Computer Security at Binghamton University in spring 2018. For more details, see the assignment document.

## Cryptography details ##

Encryption and digital signatures are implmented using [OpenSSL](https://www.openssl.org) with [RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)) key pairs.

### Encryption and decryption ###

Encryption and decryption are done with a symmetric session key rather than with the RSA asymmetric keys directly. The session key is then encrypted and decrypted using the RSA public and private keys. Specifically, [AES-256](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) is used for encryption and decryption with the session key.

For more information, see the OpenSSL wiki: [EVP Asymmetric Encryption and Decryption of an Envelope](https://wiki.openssl.org/index.php/EVP_Asymmetric_Encryption_and_Decryption_of_an_Envelope).

### Digital signatures ###

Signing and verifying digital signatures are also done using RSA key pairs. Specifically, [SHA-256](https://en.wikipedia.org/wiki/SHA-2) is the hash function used to compute the message digest.

For more information, see the OpenSSL wiki: [EVP Signing and Verifying § Asymmetric Key](https://wiki.openssl.org/index.php/EVP_Signing_and_Verifying#Asymmetric_Key).

## Running the programs ##

To run the server (voting facility, or VF):

    ./vf <port>

To run the client (voter):

    ./voter-cli <server domain> <server port>

## Generating RSA key pairs with OpenSSL ##

To generate a private key:

    openssl genrsa -out private.pem

To generate the corresponding public key:

    openssl rsa -in private.pem -pubout -out public.pem
