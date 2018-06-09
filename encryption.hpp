
/**
 * Adapted from:
 * https://wiki.openssl.org/index.php/EVP_Asymmetric_Encryption_and_Decryption_of_an_Envelope
 * https://stackoverflow.com/a/2054913
 */

#ifndef ENCRYPTION_HPP
#define ENCRYPTION_HPP

#include <cstdio>
#include <cstdlib>
#include <iostream>

#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

using namespace std;

/**
 * Encrypt the plaintext via an envelope
 * @param  rsa_pub_key_file  - the file containing the RSA public key
 * @param  plaintext         - the plaintext to encrypt
 * @param  plaintext_len     - the length of the plaintext
 * @param  encrypted_key     - the symmetric key encrypted by the public key
 * @param  encrypted_key_len - the length of the encrypted key
 * @param  iv                - the initialization vector
 * @param  ciphertext        - the result of the encryption
 * @return ciphertext_len    - the length of the ciphertext
 */
int sealEnvelope(
    FILE*           rsa_pub_key_file,
    unsigned char*  plaintext,
    int             plaintext_len,
    unsigned char** encrypted_key,
    int*            encrypted_key_len,
    unsigned char** iv,
	unsigned char** ciphertext) {
	
    EVP_PKEY* pub_key = nullptr;

    // Allocate an empty EVP_PKEY structure to store private keys
    if ((pub_key = EVP_PKEY_new()) == NULL) {
        cerr << "EVP_PKEY_new() failed" << endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    RSA* rsa_pub_key = nullptr;

    // Read the RSA public key from the file
    if (!PEM_read_RSA_PUBKEY(rsa_pub_key_file, &rsa_pub_key, NULL, NULL)) {
        cerr << "PEM_read_RSA_PUBKEY() failed" << endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Set the key referenced by pub_key to rsa_pub_key
    if (!EVP_PKEY_assign_RSA(pub_key, rsa_pub_key)) {
        cerr << "EVP_PKEY_assign_RSA() failed" << endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    EVP_CIPHER_CTX* ctx = nullptr;

    /* Create and initialise the context */
    if ((ctx = EVP_CIPHER_CTX_new()) == NULL) {
        cerr << "EVP_CIPHER_CTX_new() failed" << endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Allocate memory for the encrypted symmetric key
    if (!(*encrypted_key = (unsigned char*) OPENSSL_malloc(EVP_PKEY_size(pub_key)))) {
        cerr << "OPENSSL_malloc() failed" << endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Allocate memory for the maximum size of an initialization vector
    if (!(*iv = (unsigned char*) OPENSSL_malloc(EVP_MAX_IV_LENGTH))) {
        cerr << "OPENSSL_malloc() failed" << endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    /* Initialise the envelope seal operation. This operation generates
     * a key for the provided cipher, and then encrypts that key a number
     * of times (one for each public key provided in the pub_key array). In
     * this example the array size is just one. This operation also
     * generates an IV and places it in iv. */
    if (1 != EVP_SealInit(ctx, EVP_aes_256_cbc(), encrypted_key,
        encrypted_key_len, *iv, &pub_key, 1)) {

        cerr << "EVP_SealInit() failed" << endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);	
    }

    // Allocate memory for the ciphertext equal to the plaintext's length plus
    // extra room for padding
    if (!(*ciphertext = (unsigned char*) OPENSSL_malloc(plaintext_len + EVP_MAX_IV_LENGTH))) {
        cerr << "OPENSSL_malloc() failed" << endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    int len = 0;

    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_SealUpdate can be called multiple times if necessary
     */
    if (1 != EVP_SealUpdate(ctx, *ciphertext, &len, plaintext, plaintext_len)) {
        cerr << "EVP_SealUpdate() failed" << endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Keep track of the ciphertext length
    int ciphertext_len = len;

    /* Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if (1 != EVP_SealFinal(ctx, *ciphertext + len, &len)) {
        cerr << "EVP_SealFinal() failed" << endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Update the ciphertext length
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    EVP_PKEY_free(pub_key);

    return ciphertext_len;
}

/**
 * Decrypt the ciphertext via an envelope
 * @param  rsa_priv_key_file - the file containing the RSA private key
 * @param  ciphertext        - the ciphertext to decrypt
 * @param  ciphertext_len    - the length of the ciphertext
 * @param  encrypted_key     - the symmetric key encrypted by the public key
 * @param  encrypted_key_len - the length of the encrypted key
 * @param  iv                - the initialization vector
 * @param  plaintext         - the result of the decryption
 * @return plaintext_len     - the length of the plaintext
 */
int openEnvelope(
    FILE*           rsa_priv_key_file,
    unsigned char*  ciphertext,
    int             ciphertext_len,
    unsigned char*  encrypted_key,
    int             encrypted_key_len,
    unsigned char*  iv,
	unsigned char** plaintext) {
	
	EVP_PKEY* priv_key = nullptr;
	
    // Allocate an empty EVP_PKEY structure to store private keys
    if ((priv_key = EVP_PKEY_new()) == NULL) {
        cerr << "EVP_PKEY_new() failed" << endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    RSA* rsa_priv_key = nullptr;

    // Read the RSA private key from the file
    if (!PEM_read_RSAPrivateKey(rsa_priv_key_file, &rsa_priv_key, NULL, NULL)) {
        cerr << "PEM_read_RSAPrivateKey() failed" << endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Set the key referenced by priv_key to rsa_priv_key
    if (!EVP_PKEY_assign_RSA(priv_key, rsa_priv_key)) {
        cerr << "EVP_PKEY_assign_RSA() failed" << endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    EVP_CIPHER_CTX* ctx = nullptr;

    /* Create and initialise the context */
    if ((ctx = EVP_CIPHER_CTX_new()) == NULL) {
        cerr << "EVP_CIPHER_CTX_new() failed" << endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    };

    /* Initialise the decryption operation. The asymmetric private key is
     * provided in priv_key, whilst the encrypted session key is held in
     * encrypted_key */
    if (0 == EVP_OpenInit(ctx, EVP_aes_256_cbc(), encrypted_key,
        encrypted_key_len, iv, priv_key)) {

        cerr << "EVP_OpenInit() failed" << endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Allocate memory for the plaintext equal to the ciphertext's length plus
    // extra room for padding
    if (!(*plaintext = (unsigned char*) OPENSSL_malloc(ciphertext_len + EVP_MAX_IV_LENGTH))) {
        cerr << "OPENSSL_malloc() failed" << endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    int len = 0;

    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_OpenUpdate can be called multiple times if necessary
     */
    if (1 != EVP_OpenUpdate(ctx, *plaintext, &len, ciphertext, ciphertext_len)) {
        cerr << "EVP_OpenUpdate() failed" << endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Keep track of the plaintext length
    int plaintext_len = len;

    /* Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if (1 != EVP_OpenFinal(ctx, *plaintext + len, &len)) {
        cerr << "EVP_OpenFinal() failed" << endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Update the plaintext length
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    EVP_PKEY_free(priv_key);

    return plaintext_len;
}

#endif
