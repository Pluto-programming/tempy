//#include <iostream>
//int main() { std::cout << "Client Running" << std::endl; return 0; }

//#include <iostream>
//#include <fstream>
//#include <string>
//#include <unistd.h>
//#include <arpa/inet.h>
//#include <openssl/rand.h>
//#include "../Include/aes_utils.h"
//#include "../Include/logger.h"
//#include "../Include/shared.h"
//
//#define AUTH_PORT 5555
//#define CHAT_PORT 6666
//#define USER_KEY_FILE "../Certs/usr_key.bin"
//
//std::string session_key;
//
//std::string request_session_key(const std::string& username) {
//    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
//    sockaddr_in addr{};
//    addr.sin_family = AF_INET;
//    addr.sin_port = htons(AUTH_PORT);
//    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
//
//    connect(sockfd, (sockaddr*)&addr, sizeof(addr));
//    std::string nonce = "12345678";  // could be random
//    std::string auth_msg = username + "," + nonce;
//    send(sockfd, auth_msg.c_str(), auth_msg.size(), 0);
//
//    unsigned char user_key[32];
//    std::ifstream keyfile(USER_KEY_FILE, std::ios::binary);
//    keyfile.read((char*)user_key, 32);
//    keyfile.close();
//
//    // receive encrypted key
//    unsigned char encrypted[512], iv[12], tag[16];
//    recv(sockfd, encrypted, sizeof(encrypted), 0);
//    recv(sockfd, iv, sizeof(iv), 0);
//    recv(sockfd, tag, sizeof(tag), 0);
//
//    unsigned char* plaintext = nullptr;
//    int declen = aes_decrypt_gcm(encrypted, 512, user_key, iv, tag, &plaintext);
//    std::string decrypted_msg((char*)plaintext, declen);
//    delete[] plaintext;
//    close(sockfd);
//
//    size_t last_comma = decrypted_msg.rfind(',');
//    std::string skey = decrypted_msg.substr(last_comma - 32, 32); // assuming key is last 32 bytes
//    return skey;
//}
//
//void chat_loop(const std::string& skey) {
//    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
//    sockaddr_in addr{};
//    addr.sin_family = AF_INET;
//    addr.sin_port = htons(CHAT_PORT);
//    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
//
//    connect(sockfd, (sockaddr*)&addr, sizeof(addr));
//    std::string msg;
//    while (true) {
//        std::cout << "> ";
//        std::getline(std::cin, msg);
//        if (msg == "exit") break;
//
//        unsigned char iv[12], tag[16], encrypted[512];
//        RAND_bytes(iv, sizeof(iv));
//        int len = 0;
//        aes_encrypt_gcm((unsigned char*)msg.c_str(), msg.size(), (unsigned char*)skey.c_str(), iv, encrypted, &len, tag);
//        send(sockfd, encrypted, len, 0);
//    }
//    close(sockfd);
//}
//
//int main() {
//    log_message("[Client] Starting");
//    session_key = request_session_key("client1");
//    log_message("[Client] Got session key: " + session_key);
//    chat_loop(session_key);
//    return 0;
//}

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include "../Include/aes_utils.h"
#include "../Include/logger.h"
#include "../Include/shared.h"

#define AUTH_PORT 5555
#define CHAT_PORT 6666
#define USER_KEY_FILE "../Certs/usr_key.bin"

unsigned char session_key[32] = {0};

std::string receive_and_decrypt_payload(int sock, const unsigned char* key) {
    unsigned char encrypted[512], iv[12], tag[16];
    int enc_len = recv(sock, encrypted, sizeof(encrypted), 0);
    int iv_len = recv(sock, iv, sizeof(iv), 0);
    int tag_len = recv(sock, tag, sizeof(tag), 0);

    if (enc_len <= 0 || iv_len != 12 || tag_len != 16) {
        std::cerr << "[Client] ERROR: Failed to receive full encrypted payload\n";
        exit(1);
    }

    unsigned char* plaintext = nullptr;
    int declen = aes_decrypt_gcm(encrypted, enc_len, key, iv, tag, &plaintext);

    if (declen <= 0) {
        std::cerr << "[Client] ERROR: Decryption failed\n";
        exit(1);
    }

    std::string result((char*)plaintext, declen);
    delete[] plaintext;
    return result;
}

void request_session_key_from_auth() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(AUTH_PORT);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    connect(sock, (sockaddr*)&addr, sizeof(addr));

    std::string username = "client1";
    std::string nonce = "12345678";
    std::string auth_msg = username + "," + nonce;
    send(sock, auth_msg.c_str(), auth_msg.size(), 0);

    unsigned char user_key[32];
    std::ifstream keyfile(USER_KEY_FILE, std::ios::binary);
    if (!keyfile) {
        std::cerr << "[Client] ERROR: Unable to open user key file\n";
        exit(1);
    }
    keyfile.read((char*)user_key, 32);
    keyfile.close();

    std::string decrypted = receive_and_decrypt_payload(sock, user_key);
    std::cout << "[Client] Decrypted payload: " << decrypted << std::endl;

    size_t last_comma = decrypted.rfind(',');
    if (last_comma == std::string::npos) {
        std::cerr << "[Client] ERROR: Payload missing session key\n";
        exit(1);
    }

    std::string b64_key = decrypted.substr(last_comma + 1);
    if (b64_key.empty()) {
        std::cerr << "[Client] ERROR: Session key is empty\n";
        exit(1);
    }

    int decoded_len = EVP_DecodeBlock(session_key, (const unsigned char*)b64_key.c_str(), b64_key.length());

    // EVP_DecodeBlock always returns multiples of 3 — may add 1 null byte if base64 ended in "="
    if (decoded_len > 32) decoded_len = 32;  // trim extra byte safely

    if (decoded_len != 32) {
        std::cerr << "[Client] ERROR: Decoded session key length incorrect after trim (" << decoded_len << ")\n";
        exit(1);
    }


    std::cout << "[Client] Got session key (base64): " << b64_key << std::endl;
    close(sock);
}

void chat_loop() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(CHAT_PORT);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    connect(sock, (sockaddr*)&addr, sizeof(addr));
    std::cout << "[Client] Connected to chat server.\n";

    while (true) {
        std::string msg;
        std::cout << "> ";
        std::getline(std::cin, msg);
        if (msg == "exit") break;

        unsigned char iv[12], tag[16], encrypted[512];
        RAND_bytes(iv, sizeof(iv));
        int len = 0;
        aes_encrypt_gcm((unsigned char*)msg.c_str(), msg.size(), session_key, iv, encrypted, &len, tag);

        send(sock, encrypted, len, 0);
    }

    close(sock);
}

int main() {
    log_message("[Client] Starting...");
    request_session_key_from_auth();
    chat_loop();
    return 0;
}
