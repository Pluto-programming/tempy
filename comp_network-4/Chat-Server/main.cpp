//#include <iostream>
//int main() { std::cout << "Chat Server Running" << std::endl; return 0; }

//#include "../Include/shared.h"
//
//int main() {
//    init_openssl();
//    int sockfd = create_socket(9999);
//    log_info("Chat Server Running");
//
//    while (1) {
//        struct sockaddr_in addr;
//        uint len = sizeof(addr);
//        int client = accept(sockfd, (struct sockaddr*)&addr, &len);
//
//        unsigned char buffer[1024];
//        int len = recv(client, buffer, sizeof(buffer), 0);
//
//        unsigned char *decrypted;
//        int declen = aes_decrypt(buffer, len, load_key("../Certs/session_key.bin"), &decrypted);
//        decrypted[declen] = '\0';
//
//        log_info("[Received] %s", decrypted);
//        free(decrypted);
//        close(client);
//    }
//    return 0;
//}

//#include <iostream>
//#include <thread>
//#include <vector>
//#include <unistd.h>
//#include "../Include/shared.h"
////#include "../Src/attack_detection.h"
//
//std::vector<int> clients;
//
//void handle_client(int client) {
//    char buffer[4096];
//    while (true) {
//        int len = recv(client, buffer, sizeof(buffer), 0);
//        if (len <= 0) break;
//        buffer[len] = '\0';
//        std::string msg(buffer);
//        if (detect_attack(msg)) {
//            std::cerr << "[!] Attack detected: " << msg << std::endl;
//            continue;
//        }
//        for (int c : clients)
//            if (c != client)
//                send(c, msg.c_str(), msg.size(), 0);
//    }
//    close(client);
//}
//
//int main() {
//    int sock = create_socket(6666);
//    std::cout << "Chat Server Running\n";
//
//    while (true) {
//        int client = accept(sock, NULL, NULL);
//        if (client >= 0) {
//            clients.push_back(client);
//            std::thread(handle_client, client).detach();
//        }
//    }
//}
#include <iostream>
#include <thread>
#include <vector>
#include <mutex>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include "../Src/attack_detection.h"
#include "../Include/shared.h"

// Dummy AES encryption/decryption (replace with OpenSSL versions)
std::string aes_encrypt(const std::string &plaintext, const std::string &key) {
    return plaintext; // stub
}

std::string aes_decrypt(const std::string &ciphertext, const std::string &key) {
    return ciphertext; // stub
}

#define SESSION_KEY "mysecurekey12345"

std::vector<int> clients;
std::mutex clients_mutex;

//int create_socket(int port) {
//    int sock = socket(AF_INET, SOCK_STREAM, 0);
//    if (sock < 0) {
//        perror("socket");
//        exit(1);
//    }
//
//    int opt = 1;
//    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
//
//    sockaddr_in addr {};
//    addr.sin_family = AF_INET;
//    addr.sin_port = htons(port);
//    addr.sin_addr.s_addr = INADDR_ANY;
//
//    if (bind(sock, (sockaddr*)&addr, sizeof(addr)) < 0) {
//        perror("bind");
//        exit(1);
//    }
//
//    if (listen(sock, 5) < 0) {
//        perror("listen");
//        exit(1);
//    }
//
//    return sock;
//}

void broadcast(const std::string &msg, int sender_fd) {
    std::lock_guard<std::mutex> lock(clients_mutex);
    for (int client : clients) {
        if (client != sender_fd) {
            send(client, msg.c_str(), msg.size(), 0);
        }
    }
}

void handle_client(int client_fd) {
    char buffer[2048];
    while (true) {
        memset(buffer, 0, sizeof(buffer));
        int len = recv(client_fd, buffer, sizeof(buffer), 0);
        if (len <= 0) {
            std::cerr << "Client disconnected.\n";
            close(client_fd);
            std::lock_guard<std::mutex> lock(clients_mutex);
            clients.erase(std::remove(clients.begin(), clients.end(), client_fd), clients.end());
            break;
        }

        std::string encrypted_msg(buffer, len);
        std::string msg = aes_decrypt(encrypted_msg, SESSION_KEY);

        if (detect_attack(msg)) {
            std::cerr << "[!] Attack detected from client " << client_fd << ": " << msg << std::endl;
            continue;
        }

        std::cout << "[Client " << client_fd << "]: " << msg << std::endl;

        std::string encrypted_broadcast = aes_encrypt(msg, SESSION_KEY);
        broadcast(encrypted_broadcast, client_fd);
    }
}

int main() {
    int server_fd = create_socket(6666);
    std::cout << "[*] Chat Server Running on port 6666...\n";

    while (true) {
        int client_fd = accept(server_fd, nullptr, nullptr);
        if (client_fd < 0) {
            std::cerr << "[-] Failed to accept client\n";
            continue;
        }

        std::cout << "[+] Client connected: FD=" << client_fd << std::endl;
        {
            std::lock_guard<std::mutex> lock(clients_mutex);
            clients.push_back(client_fd);
        }

        std::thread t([client_fd]() {
            handle_client(client_fd);
        });
        t.detach();
    }

    close(server_fd);
    return 0;
}
