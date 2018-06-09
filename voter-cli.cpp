
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>

#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "encryption.hpp"
#include "signature.hpp"

using namespace std;

// Used for encryption
const char* serverPubKeyFile = "keys/server-public.pem";

// Used for digital signature encryption
const char* alicePrivKeyFile = "keys/alice-private.pem";
const char* bobPrivKeyFile   = "keys/bob-private.pem";
const char* johnPrivKeyFile  = "keys/john-private.pem";

void connectToServer(const string& hostName, const string& port);
void sendRegistration(const int& serverSocket);
void displayMenu(const string& name, const string& regNum);
void vote(const int& serverSocket);
void viewVoterHistory(const int& serverSocket, const string& regNum);
void viewResult(const int& serverSocket);

int main(int argc, char* argv[]) {
    if (argc != 3) {
        cout << "Usage: " << argv[0] << " <server domain> <server port>" << endl;
        exit(EXIT_FAILURE);
    }
    
    string serverDomain = argv[1];
    string serverPort   = argv[2];
    
    connectToServer(serverDomain, serverPort);
}

/**
 * Connect the client to the server specified via the command-line arguments
 * https://beej.us/guide/bgnet/html/multi/index.html
 * @param  hostName - the host name of the server
 * @param  port     - the port to use, in string form for use with getaddrinfo
 */
void connectToServer(const string& hostName, const string& port) {
    struct addrinfo  hints;
    struct addrinfo* results = nullptr;
    struct addrinfo* current = nullptr;
    
    memset(&hints, 0, sizeof hints);
    
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = 0;
    
    // Get one or more addrinfo structures (results) about the host specified by
    // serverDomain
    int gaiResult = getaddrinfo(
        hostName.c_str(),
        port.c_str(),
        &hints,
        &results
    );
    
    if (gaiResult != 0) {
        cerr << "getaddrinfo() failed: " << gai_strerror(gaiResult) << endl;
        exit(EXIT_FAILURE);
    }
    
    int serverSocket;
    
    // Loop through the results returned and connect to the first we can
    for (current = results; current != nullptr; current = current->ai_next) {
        // Create a socket for this client to connect to the server
        serverSocket = socket(
            current->ai_family,
            current->ai_socktype,
            current->ai_protocol
        );
        
        if (serverSocket == -1) {
            perror("socket() failed");
            continue;
        }
        
        // Connect the server socket to the address specified
        if (connect(serverSocket, current->ai_addr, current->ai_addrlen) == -1) {
            perror("connect() failed");
            close(serverSocket);
            continue;
        }
        
        // We successfully connected
        break;
    }
    
    // If we looped through all the results without being able to connect
    if (current == nullptr) {
        cerr << "Failed to connect" << endl;
        exit(EXIT_FAILURE);
    }
    
    // Free the memory allocated for the results
    freeaddrinfo(results);
    
    sendRegistration(serverSocket);
}

/**
 * Encrypt the voter name and registration number, then send the encrypted
 * message and a digital signature to the server for verification
 * @param serverSocket - the server's socket
 */
void sendRegistration(const int& serverSocket) {
    string name;
    string regNum;
    
    const char* clientPrivKeyFile;
    
    // Ensure the name is valid
    while (true) {
        cout << "Enter your credentials..." << endl << endl;
        
        cout << "Name (case-sensitive): ";
        cin >> name;
        
        cout << "Registration number:   ";
        cin >> regNum;
        
        if (name == "Alice") {
            clientPrivKeyFile = alicePrivKeyFile;
        }
        else if (name == "Bob") {
            clientPrivKeyFile = bobPrivKeyFile;
        }
        else if (name == "John") {
            clientPrivKeyFile = johnPrivKeyFile;
        }
        else {
            cout << "Voter not registered (must be Alice, Bob, or John)" << endl;
            continue;
        }
        
        break;
    }
    
    // Concatenate the name and registration number for use as the plaintext
    string plaintext = name + regNum;
    
    const    char* plaintextBuffer   = plaintext.c_str();
    unsigned char* encrypted_key     = nullptr;
    int            encrypted_key_len = 0;
    unsigned char* iv                = nullptr;
    
    // Open the file containing the server's RSA public key
    FILE* rsa_pub_key_file = fopen(serverPubKeyFile, "rb");
    
    if (rsa_pub_key_file == NULL) {
        perror("fopen() failed");
        exit(EXIT_FAILURE);
    }
    
    unsigned char* ciphertext = nullptr;
    
    // Encrypt the plaintext using the server's public key
    int ciphertext_len = sealEnvelope(
        rsa_pub_key_file,
        (unsigned char*) plaintextBuffer,
        strlen(plaintextBuffer),
        &encrypted_key,
        &encrypted_key_len,
        &iv,
        &ciphertext
    );
    
    fclose(rsa_pub_key_file);
    
    const char* nameBuffer = name.c_str();
    
    // Open the file containing the client's RSA private key
    FILE* rsa_priv_key_file = fopen(clientPrivKeyFile, "rb");
    
    if (rsa_priv_key_file == NULL) {
        perror("fopen() failed");
        exit(EXIT_FAILURE);
    }
    
    unsigned char* sig = nullptr;
    
    // Sign (encrypt) the name using the client's private key
    int sig_len = sign(
        rsa_priv_key_file,
        (const char*) nameBuffer,
        strlen(nameBuffer),
        &sig
    );
    
    fclose(rsa_priv_key_file);
    
    // 16 bytes
    const int iv_len = EVP_MAX_IV_LENGTH;
    
    int messageLen = encrypted_key_len + iv_len + ciphertext_len + sig_len;
    
    // Create a buffer to hold the encrypted symmetric key, the initialization
    // vector, the ciphertext, and the signature
    char message[messageLen];
    
    int bytesCopied = 0;
    
    // Copy the encrypted symmetric key into the message buffer
    if (memcpy((void*) message, (const void*) encrypted_key, encrypted_key_len) == NULL) {
        cerr << "memcpy() failed" << endl;
        exit(EXIT_FAILURE);
    }
    
    bytesCopied += encrypted_key_len;
    
    // Copy the initialization vector into the message buffer
    if (memcpy((void*) (message + bytesCopied), (const void*) iv, iv_len) == NULL) {
        cerr << "memcpy() failed" << endl;
        exit(EXIT_FAILURE);
    }
    
    bytesCopied += iv_len;
    
    // Copy the ciphertext into the message buffer
    if (memcpy((void*) (message + bytesCopied), (const void*) ciphertext, ciphertext_len) == NULL) {
        cerr << "memcpy() failed" << endl;
        exit(EXIT_FAILURE);
    }
    
    bytesCopied += ciphertext_len;
    
    // Copy the digital signature into the message buffer
    if (memcpy((void*) (message + bytesCopied), (const void*) sig, sig_len) == NULL) {
        cerr << "memcpy() failed" << endl;
        exit(EXIT_FAILURE);
    }
    
    // Send the message to the server
    if (send(serverSocket, (const char*) message, messageLen, 0) == -1) {
        perror("send() failed");
        exit(EXIT_FAILURE);
    }
    
    char response[1];
    
    // Block until a message arrives from the server, then receive it
    int byteCount = recv(serverSocket, response, 1, 0);
    
    if (byteCount == -1) {
        perror("recv() failed");
        exit(EXIT_FAILURE);
    }
    
    if (*response == '0') {
        cerr << "Invalid name or registration number" << endl;
        exit(EXIT_FAILURE);
    }
    
    // Must free like so since memory is allocated with OPENSSL_malloc
    OPENSSL_free(encrypted_key);
    OPENSSL_free(iv);
    OPENSSL_free(ciphertext);
    OPENSSL_free(sig);
    
    displayMenu(serverSocket, name, regNum);
}

/**
 * Display the main menu
 * @param serverSocket - the server's socket
 * @param name         - the voter's name
 */
void displayMenu(const int& serverSocket, const string& name, const string& regNum) {
    while (true) {
        cout << endl << "Welcome, " << name << endl;
        cout << "Main Menu" << endl;
        cout << "Please enter a number (1-4)" << endl;
        cout << "1. Vote" << endl;
        cout << "2. My vote history" << endl;
        cout << "3. Election result" << endl;
        cout << "4. Quit" << endl;
        
        string input;
        
        cout << "> ";
        cin  >> input;
        
        if (input == "1") {
            vote(serverSocket);
        }
        else if (input == "2") {
            viewVoterHistory(serverSocket, regNum);
        }
        else if (input == "3") {
            viewResult(serverSocket);
        }
        else if (input == "4") {
            break;
        }
        else {
            cout << "Invalid number" << endl;
        }
    }
}

/**
 * If the user hasn't already voted, let them vote, encrypt the vote, and send
 * it to the server
 * @param serverSocket - the server's socket
 */
void vote(const int& serverSocket) {
    // Have the server check whether the user has already voted
    if (send(serverSocket, "1", 1, 0) == -1) {
        perror("send() failed");
        exit(EXIT_FAILURE);
    }
    
    char response[1];
    
    // Get the server's response
    if (recv(serverSocket, response, 1, 0) == -1) {
        perror("recv() failed");
        exit(EXIT_FAILURE);
    }
    
    // If the user has already voted, return to the main menu
    if (*response == '0') {
        cout << "you have already voted" << endl;
        return;
    }
    
    string input;
    
    // Loop until the voter picks a candidate
    while (true) {
        cout << "Please enter a number (1-2)" << endl;
        cout << "1. Tim" << endl;
        cout << "2. Linda" << endl;
        
        cout << "> ";
        cin  >> input;
        
        // Encrypt the vote and send it
        if (input == "1" || input == "2") {
            break;
        }
        
        cout << "Invalid number" << endl << endl;
    }
    
    const    char* plaintextBuffer   = input.c_str();
    unsigned char* encrypted_key     = nullptr;
    int            encrypted_key_len = 0;
    unsigned char* iv                = nullptr;
    
    // Open the file containing the server's RSA public key
    FILE* rsa_pub_key_file = fopen(serverPubKeyFile, "rb");
    
    if (rsa_pub_key_file == NULL) {
        perror("fopen() failed");
        exit(EXIT_FAILURE);
    }
    
    unsigned char* ciphertext = nullptr;
    
    // Encrypt the plaintext using the server's public key
    int ciphertext_len = sealEnvelope(
        rsa_pub_key_file,
        (unsigned char*) plaintextBuffer,
        strlen(plaintextBuffer),
        &encrypted_key,
        &encrypted_key_len,
        &iv,
        &ciphertext
    );
    
    fclose(rsa_pub_key_file);
    
    // FIXME: Move below code duplicated from sendRegistration to utility function
    // (Or put everything into one buffer from the start to avoid copying?)
    
    // 16 bytes
    const int iv_len = EVP_MAX_IV_LENGTH;
    
    int messageLen = encrypted_key_len + iv_len + ciphertext_len;
    
    // Create a buffer to hold the encrypted symmetric key, the initialization
    // vector, the ciphertext, and the signature
    char message[messageLen];
    
    int bytesCopied = 0;
    
    // Copy the encrypted symmetric key into the message buffer
    if (memcpy((void*) message, (const void*) encrypted_key, encrypted_key_len) == NULL) {
        cerr << "memcpy() failed" << endl;
        exit(EXIT_FAILURE);
    }
    
    bytesCopied += encrypted_key_len;
    
    // Copy the initialization vector into the message buffer
    if (memcpy((void*) (message + bytesCopied), (const void*) iv, iv_len) == NULL) {
        cerr << "memcpy() failed" << endl;
        exit(EXIT_FAILURE);
    }
    
    bytesCopied += iv_len;
    
    // Copy the ciphertext into the message buffer
    if (memcpy((void*) (message + bytesCopied), (const void*) ciphertext, ciphertext_len) == NULL) {
        cerr << "memcpy() failed" << endl;
        exit(EXIT_FAILURE);
    }
    
    // FIXME: End of duplicated code
    
    // Send the encrypted vote to the server
    if (send(serverSocket, message, messageLen, 0) == -1) {
        perror("send() failed");
        exit(EXIT_FAILURE);
    }
    
    cout << "Vote sent!" << endl;
    
    OPENSSL_free(encrypted_key);
    OPENSSL_free(iv);
    OPENSSL_free(ciphertext);
}

/**
 * Get the voter's entry in the history file from the server and display it
 * @param serverSocket - the server's socket
 * @param regNum       - the voter's registration number
 */
void viewVoterHistory(const int& serverSocket, const string& regNum) {
    // Request the server send this user's voting history
    if (send(serverSocket, "2", 1, 0) == -1) {
        perror("send() failed");
        exit(EXIT_FAILURE);
    }
    
    const int responseSize = 128;
    
    char response[responseSize];
    
    int byteCount = 0;
    
    // Get the server's response
    if ((byteCount = recv(serverSocket, response, responseSize - 1, 0)) == -1) {
        perror("recv() failed");
        exit(EXIT_FAILURE);
    }
    
    response[byteCount] = '\0';
    
    // Print the record
    cout << response << endl;
}

/**
 * Get the election result from the server if it's available and display it
 * @param serverSocket - the server's socket
 */
void viewResult(const int& serverSocket) {
    // Request the server send this user's voting history
    if (send(serverSocket, "3", 1, 0) == -1) {
        perror("send() failed");
        exit(EXIT_FAILURE);
    }
    
    const int responseSize = 128;
    
    char response[responseSize];
    
    int byteCount = 0;
    
    // Get the server's response
    if ((byteCount = recv(serverSocket, response, responseSize - 1, 0)) == -1) {
        perror("recv() failed");
        exit(EXIT_FAILURE);
    }
    
    response[byteCount] = '\0';
    
    if (*response == '0') {
        cout << "the result is not available" << endl;
        return;
    }
    
    // Print the result
    cout << response << endl;
}
