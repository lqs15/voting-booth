
/**
 * Adapted from:
 * https://wiki.openssl.org/index.php/EVP_Signing_and_Verifying#Asymmetric_Key
 */

#ifndef SIGNATURE_HPP
#define SIGNATURE_HPP

#include <cstdio>
#include <cstdlib>
#include <iostream>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>

using namespace std;

/**
 * Digitally sign the plaintext via an envelope
 * @param  rsa_priv_key_file - the file containing the RSA private key
 * @param  plaintext         - the plaintext to encrypt
 * @param  plaintext_len     - the length of the plaintext
 * @param  sig               - the result of the encryption
 * @return slen              - the length of the ciphertext
 */
int sign(
    FILE*           rsa_priv_key_file,
    const char*     plaintext,
    int             plaintext_len,
    unsigned char** sig) {
    
    RSA* rsa_priv_key = nullptr;
    
    // Read the RSA private key from the file
    if (!PEM_read_RSAPrivateKey(rsa_priv_key_file, &rsa_priv_key, NULL, NULL)) {
        cerr << "PEM_read_RSAPrivateKey() failed" << endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    EVP_PKEY* priv_key = nullptr;

    // Allocate an empty EVP_PKEY structure to store private keys
    if ((priv_key = EVP_PKEY_new()) == NULL) {
        cerr << "EVP_PKEY_new() failed" << endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Set the key referenced by priv_key to rsa_priv_key
    if (!EVP_PKEY_assign_RSA(priv_key, rsa_priv_key)) {
        cerr << "EVP_PKEY_assign_RSA() failed" << endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    EVP_MD_CTX* mdctx = nullptr;

    /* Create the Message Digest Context */
    if (!(mdctx = EVP_MD_CTX_create())) {
        cerr << "EVP_MD_CTX_create() failed" << endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    const EVP_MD* md = EVP_sha256();

    // Set the digest type to be SHA-256
    if (1 != EVP_DigestInit_ex(mdctx, md, NULL)) {
        cerr << "EVP_DigestInit_ex() failed" << endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    /* Initialise the DigestSign operation - SHA-256 has been selected as the message digest
     * function in this example */
    if (1 != EVP_DigestSignInit(mdctx, NULL, md, NULL, priv_key)) {
        cerr << "EVP_DigestSignInit() failed" << endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    /* Call update with the message */
    if (1 != EVP_DigestSignUpdate(mdctx, plaintext, plaintext_len)) {
        cerr << "EVP_DigestSignUpdate() failed" << endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    size_t slen;

    /* Finalise the DigestSign operation */
    /* First call EVP_DigestSignFinal with a NULL sig parameter to obtain the length of the
     * signature. Length is returned in slen */
    if (1 != EVP_DigestSignFinal(mdctx, NULL, &slen)) {
        cerr << "EVP_DigestSignFinal() failed" << endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    /* Allocate memory for the signature based on size in slen */
    if (!(*sig = (unsigned char*) OPENSSL_malloc(sizeof (unsigned char) * slen))) {
        cerr << "OPENSSL_malloc() failed" << endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    /* Obtain the signature */
    if (1 != EVP_DigestSignFinal(mdctx, *sig, &slen)) {
        cerr << "EVP_DigestSignFinal() failed" << endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    /* Clean up */
    EVP_MD_CTX_destroy(mdctx);
    EVP_PKEY_free(priv_key);

    return slen;
}

/**
 * Verify the digital signature via an envelope
 * @param  rsa_pub_key_file - the file containing the RSA public key
 * @param  plaintext        - the text that should be within the encrypted sig
 * @param  plaintext_len    - the length of the plaintext
 * @param  sig              - the signature to decrypt
 * @param  slen             - the length of the signature
 */
void verifySignature(
    FILE*           rsa_pub_key_file,
    unsigned char*  plaintext,
    int             plaintext_len,
    unsigned char*  sig,
    int             slen) {
    
    RSA* rsa_pub_key = nullptr;

    // Read the RSA public key from the file
    if (!PEM_read_RSA_PUBKEY(rsa_pub_key_file, &rsa_pub_key, NULL, NULL)) {
        cerr << "PEM_read_RSA_PUBKEY() failed" << endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    EVP_PKEY* pub_key = nullptr;

    // Allocate an empty EVP_PKEY structure to store private keys
    if ((pub_key = EVP_PKEY_new()) == NULL) {
        cerr << "EVP_PKEY_new() failed" << endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Set the key referenced by pub_key to rsa_pub_key
    if (!EVP_PKEY_assign_RSA(pub_key, rsa_pub_key)) {
        cerr << "EVP_PKEY_assign_RSA() failed" << endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    EVP_MD_CTX* mdctx = nullptr;

    /* Create the Message Digest Context */
    if (!(mdctx = EVP_MD_CTX_create())) {
        cerr << "EVP_MD_CTX_create() failed" << endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    const EVP_MD* md = EVP_sha256();

    // Set the digest type to be SHA-256
    if (1 != EVP_DigestInit_ex(mdctx, md, NULL)) {
        cerr << "EVP_DigestInit_ex() failed" << endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    /* Initialise the DigestVerify operation - SHA-256 has been selected as the message digest
     * function in this example */
    if (1 != EVP_DigestVerifyInit(mdctx, NULL, md, NULL, pub_key)) {
        cerr << "EVP_DigestVerifyInit() failed" << endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    /* Call update with the signature */
    if (1 != EVP_DigestVerifyUpdate(mdctx, plaintext, plaintext_len)) {
        cerr << "EVP_DigestVerifyUpdate() failed" << endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }


    /* Clear any errors for the call below */
    ERR_clear_error();

    /* Obtain the plaintext */
    if (1 != EVP_DigestVerifyFinal(mdctx, sig, slen)) {
        cerr << "EVP_DigestVerifyFinal() failed" << endl;
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    /* Clean up */
    EVP_MD_CTX_destroy(mdctx);
    EVP_PKEY_free(pub_key);
}

#endif
