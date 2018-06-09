
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "encryption.hpp"
#include "signature.hpp"

using namespace std;

// Used for decryption
const char* serverPrivKeyFile = "keys/server-private.pem";

// Used for digital signature decryption
const char* alicePubKeyFile = "keys/alice-public.pem";
const char* bobPubKeyFile   = "keys/bob-public.pem";
const char* johnPubKeyFile  = "keys/john-public.pem";

const char* voterInfoFileName = "voterinfo";
const char* historyFileName   = "history";
const char* resultFileName    = "result";

void  startServer(const int& port);
void* requestHandler(void* clientSockPointer);
void  verifyRegistration(const int& clientSocket);
void  handleMenuOption(const int& clientSocket, const string& regNum);
void  vote(const int& clientSocket, const string& regNum);
void  viewVoterHistory(const int& clientSocket, const string& regNum);
void  viewResult(const int& clientSocket);

int main(int argc, char* argv[]) {
    if (argc != 2) {
        cout << "Usage: " << argv[0] << " <port>" << endl;
        exit(EXIT_FAILURE);
    }
    
    int port = stoi(argv[1]);
    
    startServer(port);
}

/**
 * Perform all setup necessary to serve client requests
 * https://beej.us/guide/bgnet/html/multi/index.html
 * @param port - the port the server should listen on
 */
void startServer(const int& port) {
    // Create a TCP socket
    int mySock = socket(AF_INET, SOCK_STREAM, 0);
    
    if (mySock == -1) {
        perror("socket() failed");
        exit(EXIT_FAILURE);
    }
    
    struct sockaddr_in myAddr;
    
    memset(&myAddr, 0, sizeof myAddr);
    
    myAddr.sin_family      = AF_INET;
    myAddr.sin_addr.s_addr = htonl(INADDR_ANY); // Use this machine's IP address
    myAddr.sin_port        = htons(port);
    
    // Bind the IP address and port to the socket
    if (bind(mySock, (sockaddr*) &myAddr, sizeof myAddr) == -1) {
        perror("bind() failed");
        exit(EXIT_FAILURE);
    }
    
    const int backlogSize = 50;
    
    // Listen for connection requests
    if (listen(mySock, backlogSize) == -1) {
        perror("listen() failed");
        exit(EXIT_FAILURE);
    }
    
    // Wait for connection requests from clients
    while (true) {
        struct sockaddr_in clientAddr;
        
        memset(&clientAddr, 0, sizeof clientAddr);
        
        socklen_t saLength = sizeof clientAddr;
        
        // Block until a connection request arrives.
        // Accept the connection request to the server's socket, create a new
        // connected socket for the client, and return a file descriptor
        // referring to that socket.
        int clientSock = accept(mySock, (sockaddr*) &clientAddr, &saLength);
        
        if (clientSock == -1) {
            perror("accept() failed");
            exit(EXIT_FAILURE);
        }
        
        pthread_t thread;
        
        int r = pthread_create(&thread, NULL, requestHandler, (void*) &clientSock);
        
        if (r != 0) {
            errno = r;
            perror("pthread_create() failed");
            exit(EXIT_FAILURE);
        }
    }
}

/**
 * Handle a connection request from the client
 * @param clientSockPointer - a pointer to the client's socket
 */
void* requestHandler(void* clientSockPointer) {
    const int clientSocket = *((int*) clientSockPointer);
    
    verifyRegistration(clientSocket);
}

/**
 * Receive the encrypted voter name, registration number, and digital signature
 * from the client; decrypt them; verify them; and send a response
 * @param clientSocket - the client's socket
 */
void verifyRegistration(const int& clientSocket) {
    const int messageBufferSize = 1024;
    
    char messageBuffer[messageBufferSize];
    
    // Block until a message arrives from the client, then receive it
    int byteCount = recv(clientSocket, messageBuffer, messageBufferSize, 0);
    
    if (byteCount == -1) {
        perror("recv() failed");
        exit(EXIT_FAILURE);
    }
    
    const int encrypted_key_len = 256;
    const int iv_len            = EVP_MAX_IV_LENGTH;
    const int ciphertext_len    = 16;
    const int sig_len           = 256;
    
    // Create buffers for the different parts of the message
    unsigned char encrypted_key[encrypted_key_len];
    unsigned char iv[iv_len];
    unsigned char ciphertext[ciphertext_len];
    unsigned char sig[sig_len];
    
    int bytesCopied = 0;
    
    // Copy the encrypted symmetric key into its buffer
    if (memcpy((void*) encrypted_key, (const void*) messageBuffer, encrypted_key_len) == NULL) {
        cerr << "memcpy() failed" << endl;
        exit(EXIT_FAILURE);
    }
    
    bytesCopied += encrypted_key_len;
    
    // Copy the initialization vector into its buffer
    if (memcpy((void*) iv, (const void*) (messageBuffer + bytesCopied), iv_len) == NULL) {
        cerr << "memcpy() failed" << endl;
        exit(EXIT_FAILURE);
    }
    
    bytesCopied += iv_len;
    
    // Copy the ciphertext into its buffer
    if (memcpy((void*) ciphertext, (const void*) (messageBuffer + bytesCopied), ciphertext_len) == NULL) {
        cerr << "memcpy() failed" << endl;
        exit(EXIT_FAILURE);
    }
    
    bytesCopied += ciphertext_len;
    
    // Copy the encrypted signature into its buffer
    if (memcpy((void*) sig, (const void*) (messageBuffer + bytesCopied), sig_len) == NULL) {
        cerr << "memcpy() failed" << endl;
        exit(EXIT_FAILURE);
    }
    
    unsigned char* plaintext = nullptr;
    
    // Open the file containing the server's RSA private key
    FILE* rsa_priv_key_file = fopen(serverPrivKeyFile, "rb");
    
    if (rsa_priv_key_file == NULL) {
        perror("fopen() failed");
        exit(EXIT_FAILURE);
    }
    
    // Decrypt the ciphertext using the server's private key
    int plaintext_len = openEnvelope(
        rsa_priv_key_file,
        ciphertext,
        ciphertext_len,
        encrypted_key,
        encrypted_key_len,
        iv,
        &plaintext
    );
    
    fclose(rsa_priv_key_file);
    
    // Terminate the C string (overwriting padding if it's present)
    plaintext[plaintext_len] = '\0';
    
    const int regNumLen = 9;
    
    int nameLen = plaintext_len - regNumLen;
    
    // Copy the name from the plaintext
    string name((const char*) plaintext, nameLen);
    
    // Copy the voter registration number from the plaintext
    string regNum((const char*) (plaintext + nameLen));
    
    const char* clientPubKeyFile = nullptr;
    
    if (name == "Alice") {
        clientPubKeyFile = alicePubKeyFile;
    }
    else if (name == "Bob") {
        clientPubKeyFile = bobPubKeyFile;
    }
    else if (name == "John") {
        clientPubKeyFile = johnPubKeyFile;
    }
    else {
        cerr << "Voter not registered (must be Alice, Bob, or John)" << endl;
        exit(EXIT_FAILURE);
    }
    
    // Open the file containing the client's RSA public key
    FILE* rsa_pub_key_file = fopen(clientPubKeyFile, "rb");
    
    if (rsa_pub_key_file == NULL) {
        perror("fopen() failed");
        exit(EXIT_FAILURE);
    }
    
    // Decrypt the digital signature using the client's public key
    verifySignature(
        rsa_pub_key_file,
        (unsigned char*) name.c_str(),
        name.size(),
        sig,
        sig_len
    );
    
    fclose(rsa_pub_key_file);
    
    bool voterInfoMatches = false;
    
    ifstream voterInfoFile(voterInfoFileName);
    
    // Check if the plaintext matches the info in the voter info file
    if (voterInfoFile.is_open()) {
        string line;
        
        while (getline(voterInfoFile, line)) {
            string lineName;
            string lineRegNum;
            
            stringstream ss(line);
            
            ss >> lineName >> lineRegNum;
            
            if (lineName == name && lineRegNum == regNum) {
                voterInfoMatches = true;
                break;
            }
        }
        
        voterInfoFile.close();
    }
    else {
        cerr << "Error opening file" << endl;
        exit(EXIT_FAILURE);
    }
    
    // If the voter name and registration number don't both match, let the
    // client know
    if (!voterInfoMatches) {
        if (send(clientSocket, "0", 1, 0) == -1) {
            perror("send() failed");
            exit(EXIT_FAILURE);
        }
    }
    // Otherwise, let the client know verification was successful
    else {
        if (send(clientSocket, "1", 1, 0) == -1) {
            perror("send() failed");
            exit(EXIT_FAILURE);
        }
        
        handleMenuOption(clientSocket, regNum);
    }
    
    OPENSSL_free(plaintext);
}

/**
 * Receive the menu option sent by the client and call the relevant function to
 * handle the option
 * @param clientSocket - the client's socket
 * @param regNum       - the client's voter registration number
 */
void handleMenuOption(const int& clientSocket, const string& regNum) {
    // Loop until the client quits
    while (true) {
        char option[1];
        
        // Block until the client has sent which menu option the user picked
        if (recv(clientSocket, option, 1, 0) == -1) {
            perror("recv() failed");
            exit(EXIT_FAILURE);
        }
        
        if (*option == '1') {
            vote(clientSocket, regNum);
        }
        else if (*option == '2') {
            viewVoterHistory(clientSocket, regNum);
        }
        else if (*option == '3') {
            viewResult(clientSocket);
        }
        else {
            cerr << "Invalid option" << endl;
        }
    }
}

/**
 * Allow the voter to vote if they haven't already, then update the result and
 * history files; check if all voters have voted and display the result if so
 * @param clientSocket - the client's socket
 * @param regNum       - the client's voter registration number
 */
void vote(const int& clientSocket, const string& regNum) {
    bool hasVoted = false;
    
    int historyFileLineCount = 0;
    
    // Check if the user's voter registration number is already in the file
    // (if so, they've already voted)
    fstream historyFile(historyFileName, ios::in | ios::out | ios::app);
    
    if (historyFile.is_open()) {
        string line;
        
        while (getline(historyFile, line)) {
            historyFileLineCount++;
            
            string lineRegNum;
            
            stringstream ss(line);
            
            ss >> lineRegNum;
            
            if (lineRegNum == regNum) {
                hasVoted = true;
                break;
            }
        }
        
        historyFile.close();
    }
    else {
        cerr << "Error opening history file (the first time)" << endl;
        exit(EXIT_FAILURE);
    }
    
    // Clear the file stream so it can be reused
    historyFile.clear();
    
    // If the user has already voted, let the client know
    if (hasVoted) {
        if (send(clientSocket, "0", 1, 0) == -1) {
            perror("send() failed");
            exit(EXIT_FAILURE);
        }
        
        return;
    }
    
    // Otherwise, allow the client to vote
    if (send(clientSocket, "1", 1, 0) == -1) {
        perror("send() failed");
        exit(EXIT_FAILURE);
    }
    
    // FIXME: Move below code duplicated from verifyRegistration to utility function
    // (Or put everything into one buffer from the start to avoid copying?)
    
    const int messageBufferSize = 1024;
    
    char messageBuffer[messageBufferSize];
    
    // Block until a message arrives from the client, then receive it
    int byteCount = recv(clientSocket, messageBuffer, messageBufferSize, 0);
    
    if (byteCount == -1) {
        perror("recv() failed");
        exit(EXIT_FAILURE);
    }
    
    const int encrypted_key_len = 256;
    const int iv_len            = EVP_MAX_IV_LENGTH;
    const int ciphertext_len    = 16;
    
    // Create buffers for the different parts of the message
    unsigned char encrypted_key[encrypted_key_len];
    unsigned char iv[iv_len];
    unsigned char ciphertext[ciphertext_len];
    
    int bytesCopied = 0;
    
    // Copy the encrypted symmetric key into its buffer
    if (memcpy((void*) encrypted_key, (const void*) messageBuffer, encrypted_key_len) == NULL) {
        cerr << "memcpy() failed" << endl;
        exit(EXIT_FAILURE);
    }
    
    bytesCopied += encrypted_key_len;
    
    // Copy the initialization vector into its buffer
    if (memcpy((void*) iv, (const void*) (messageBuffer + bytesCopied), iv_len) == NULL) {
        cerr << "memcpy() failed" << endl;
        exit(EXIT_FAILURE);
    }
    
    bytesCopied += iv_len;
    
    // Copy the ciphertext into its buffer
    if (memcpy((void*) ciphertext, (const void*) (messageBuffer + bytesCopied), ciphertext_len) == NULL) {
        cerr << "memcpy() failed" << endl;
        exit(EXIT_FAILURE);
    }
    
    unsigned char* plaintext = nullptr;
    
    // Open the file containing the server's RSA private key
    FILE* rsa_priv_key_file = fopen(serverPrivKeyFile, "rb");
    
    if (rsa_priv_key_file == NULL) {
        perror("fopen() failed");
        exit(EXIT_FAILURE);
    }
    
    // Decrypt the ciphertext using the server's private key
    int plaintext_len = openEnvelope(
        rsa_priv_key_file,
        ciphertext,
        ciphertext_len,
        encrypted_key,
        encrypted_key_len,
        iv,
        &plaintext
    );
    
    fclose(rsa_priv_key_file);
    
    // Terminate the C string (overwriting padding if it's present)
    plaintext[plaintext_len] = '\0';
    
    // FIXME: End of duplicated code
    
    int timVoteCount   = 0;
    int lindaVoteCount = 0;
    
    // Open the result file or create it if it doesn't exist
    fstream resultFile(resultFileName, ios::in | ios::out | ios::app);
    
    // Get correct vote counts from the file if they exist (rather than zeros)
    if (resultFile.is_open()) {
        string line;
        
        bool onFirstLine = true;
        
        while (getline(resultFile, line)) {
            stringstream ss(line);
            
            // Not used
            string candidateName;
            
            string lineVoteCount;
            
            ss >> candidateName >> lineVoteCount;
            
            if (onFirstLine) {
                timVoteCount = stoi(lineVoteCount);
            }
            else {
                lindaVoteCount = stoi(lineVoteCount);
            }
            
            onFirstLine = false;
        }
        
        resultFile.close();
    }
    else {
        cerr << "Error opening result file (first time)" << endl;
        exit(EXIT_FAILURE);
    }
    
    // Clear the file stream so it can be reused
    resultFile.clear();
    
    // Increment the vote count the user voted for
    if (*plaintext == '1') {
        timVoteCount++;
    }
    else if (*plaintext == '2') {
        lindaVoteCount++;
    }
    else {
        cerr << "Invalid choice" << endl;
    }
    
    // Reopen the result file, this time erasing all its contents
    resultFile.open(resultFileName, ios::out | ios::trunc);
    
    // Write the updated vote counts to the file
    if (resultFile.is_open()) {
        resultFile << "Tim   " << timVoteCount   << endl;
        resultFile << "Linda " << lindaVoteCount << endl;
        
        resultFile.close();
    }
    else {
        cerr << "Error opening result file (second time)" << endl;
        exit(EXIT_FAILURE);
    }
    
    // Get the current time to write to the file
    time_t rawTime = time(NULL);
        
    struct tm* timeInfo = localtime(&rawTime);
    
    if (timeInfo == NULL) {
        perror("localtime() failed");
        exit(EXIT_FAILURE);
    }
    
    char timestampBuffer[256];
    
    // Write the timestamp in the current locale's preferred format into the buffer
    byteCount = strftime(timestampBuffer, sizeof timestampBuffer, "%c", timeInfo);
    
    if (byteCount == 0) {
        cerr << "strftime() failed" << endl;
        exit(EXIT_FAILURE);
    }
    
    string timestamp(timestampBuffer, byteCount);
    
    // Reopen the history file, appending to its contents
    historyFile.open(historyFileName, ios::out | ios::app);
    
    if (historyFile.is_open()) {
        historyFile << regNum << " " << timestamp << endl;
        
        historyFile.close();
    }
    else {
        cerr << "Error opening history file (the second time)" << endl;
        exit(EXIT_FAILURE);
    }
    
    historyFileLineCount++;
    
    // If all 3 voters have voted
    if (historyFileLineCount == 3) {
        string winner;
        
        if (timVoteCount > lindaVoteCount) {
            winner = "Tim";
        }
        else if (lindaVoteCount > timVoteCount) {
            winner = "Linda";
        }
        else {
            cerr << "Vote counts are equal (this shouldn't happen)!" << endl;
            exit(EXIT_FAILURE);
        }
        
        cout << winner << " Win" << endl;
        cout << "Tim   " << timVoteCount   << endl;
        cout << "Linda " << lindaVoteCount << endl;
    }
    
    OPENSSL_free(plaintext);
}

/**
 * Get the voter's entry in the history file and send it to the client if
 * it exists
 * @param clientSocket - the client's socket
 * @param regNum       - the client's voter registration number
 */
void viewVoterHistory(const int& clientSocket, const string& regNum) {
    string historyRecord;
    
    bool recordFound = false;
    
    ifstream historyFile(historyFileName);
    
    if (historyFile.is_open()) {
        string line;
        
        while (getline(historyFile, line)) {
            stringstream ss(line);
            
            string lineRegNum;
            
            ss >> lineRegNum;
            
            if (lineRegNum == regNum) {
                historyRecord = line;
                recordFound = true;
                break;
            }
        }
        
        historyFile.close();
    }
    else {
        cerr << "Error opening history file" << endl;
        exit(EXIT_FAILURE);
    }
    
    if (!recordFound) {
        historyRecord = "No record";
    }
    
    if (send(clientSocket, historyRecord.c_str(), historyRecord.size(), 0) == -1) {
        perror("send() failed");
        exit(EXIT_FAILURE);
    }
}

/**
 * Check the history file to see if all voters have voted; if so, get the vote
 * counts from the result file, then display them and send them to the client
 * @param clientSocket - the client's socket
 */
void viewResult(const int& clientSocket) {
    int historyFileLineCount = 0;
    
    ifstream historyFile(historyFileName);
    
    if (historyFile.is_open()) {
        string line;
        
        while (getline(historyFile, line)) {
            historyFileLineCount++;
        }
        
        historyFile.close();
    }
    else {
        cerr << "Error opening history file" << endl;
        exit(EXIT_FAILURE);
    }
    
    if (historyFileLineCount != 3) {
        if (send(clientSocket, "0", 1, 0) == -1) {
            perror("send() failed");
            exit(EXIT_FAILURE);
        }
        
        return;
    }
    
    // FIXME: logic copied from other function...
    
    int timVoteCount   = 0;
    int lindaVoteCount = 0;
    
    // Open the result file or create it if it doesn't exist
    fstream resultFile(resultFileName, ios::in | ios::out | ios::app);
    
    // Get correct vote counts from the file if they exist (rather than zeros)
    if (resultFile.is_open()) {
        string line;
        
        bool onFirstLine = true;
        
        while (getline(resultFile, line)) {
            stringstream ss(line);
            
            // Not used
            string candidateName;
            
            string lineVoteCount;
            
            ss >> candidateName >> lineVoteCount;
            
            if (onFirstLine) {
                timVoteCount = stoi(lineVoteCount);
            }
            else {
                lindaVoteCount = stoi(lineVoteCount);
            }
            
            onFirstLine = false;
        }
        
        resultFile.close();
    }
    else {
        cerr << "Error opening result file" << endl;
        exit(EXIT_FAILURE);
    }
    
    string winner;
    
    if (timVoteCount > lindaVoteCount) {
        winner = "Tim";
    }
    else if (lindaVoteCount > timVoteCount) {
        winner = "Linda";
    }
    else {
        cerr << "Vote counts are equal (this shouldn't happen)!" << endl;
        exit(EXIT_FAILURE);
    }
    
    string message = "";
    
    message += winner;
    message += " Win\n";
    message += "Tim   ";
    message += to_string(timVoteCount);
    message += "\n";
    message += "Linda ";
    message += to_string(lindaVoteCount);
    message += "\n";
    
    if (send(clientSocket, message.c_str(), message.size(), 0) == -1) {
        perror("send() failed");
        exit(EXIT_FAILURE);
    }
}
