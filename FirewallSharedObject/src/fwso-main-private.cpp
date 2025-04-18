#include "fwso-main.hpp"

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <filesystem>
#include <fstream>
#include <algorithm>
#include <openssl/rand.h>
#include <vector>
#include <keyutils.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <iostream>
#include <string>
#include <stdexcept>

#include "utils.hpp"

namespace fwso::api {

    void fwso_api::init() {
        for (const auto &entry: filesystem::directory_iterator("/proc")) {
            if (!entry.is_directory()) continue;
            string pid = entry.path().filename().string();
            if (!ranges::all_of(pid.begin(), pid.end(), ::isdigit)) continue;
            ifstream cmd_file(entry.path() / "cmdline");
            string cmd_line;
            if (cmd_file && getline(cmd_file, cmd_line)) {
                if (cmd_line.find(FIREWALL_SERVICE_NAME) != string::npos) {
                    firewall_service_pid = stol(pid);
                    break;
                }
            }
        }
        if (firewall_service_pid == -1)
            perror("The firewall service could not be found!");
    }

    int fwso_api::uds_connect() {
        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd == -1) {
            perror("socket");
            return -1;
        }
        sockaddr_un addr = {};
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, SOCKET_PATH.c_str(), sizeof(addr.sun_path) - 1);

        if (connect(fd, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) == -1) {
            perror("connect");
            close(fd);
            return -1;
        }
        log_queue.emplace("Socket connected, TCP connect initialized;");
        return fd;
    }

    /**
     * Generates a secure AES key and stores it in the Linux Kernel Keyring.
     */
    key_serial_t fwso_api::create_secure_AES_key() {
        unsigned char key[AES_KEY_SIZE];

        // Generate a random AES key
        if (RAND_bytes(key, AES_KEY_SIZE) != 1) {
            perror("Failed to generate AES key.");
            return -1;
        }

        // Store the key in the kernel keyring
        key_serial_t key_id = add_key("user", AES_KEYRING_NAME, key, AES_KEY_SIZE, KEY_SPEC_SESSION_KEYRING);
        if (key_id == -1) {
            perror("Failed to store AES key in keyring");
        } else {
            log_queue.emplace("AES key securely stored in kernel keyring.");
        }

        // Securely erase local key copy
        memset(key, 0, AES_KEY_SIZE);
        return key_id;
    }

    /**
     * Retrieves the AES key from the Linux Kernel Keyring.
     */
    vector<unsigned char> fwso_api::get_secure_AES_key(key_serial_t key_id) {
        vector<unsigned char> key(AES_KEY_SIZE);

        if (const ssize_t len = keyctl(KEYCTL_READ, key_id, key.data(), AES_KEY_SIZE, 0); len == -1) {
            perror("Failed to retrieve AES key from keyring");
            return {};
        }

        return key;
    }

    /**
     * Securely removes the AES key from the keyring.
     */
    void fwso_api::remove_secure_AES_key(key_serial_t key_id) {
        if (keyctl(KEYCTL_INVALIDATE, key_id, 0, 0, 0) == -1) {
            perror("Failed to remove AES key from keyring");
        } else {
            log_queue.emplace("AES key removed from keyring.");
        }
    }

    vector<unsigned char> base64_decode(const string &encoded) {
        BIO *bio, *b64;
        int decodeLen = encoded.size();
        vector<unsigned char> buffer(decodeLen);

        bio = BIO_new_mem_buf(encoded.data(), encoded.size());
        b64 = BIO_new(BIO_f_base64());
        bio = BIO_push(b64, bio);
        BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // No newlines

        BIO_free_all(bio);

        return buffer;
    }

    void fwso_api::send_message(const string &message, string &resp) {
        if (send(sockfd, message.c_str(), message.size(), 0) == -1) {
            perror("send");
            return;
        }
        log_queue.push("Message sent: " + message);

        char buffer[1024] = {0};
        ssize_t bytes_received = recv(sockfd, buffer, sizeof(buffer) -1, 0);
        if (bytes_received == -1)
            perror("recv");
        else {
            buffer[bytes_received] = '\0';
            resp = string(buffer, bytes_received);
        }
    }
    RSA* load_public_key() {
        ifstream key_file("/etc/firewall/public.key");
        if (!key_file) {
            cerr << "Error: Could not open RSA public key file." << endl;
            return nullptr;
        }

        string key_base64((istreambuf_iterator<char>(key_file)), istreambuf_iterator<char>());
        key_file.close();

        BIO *bio = BIO_new_mem_buf(key_base64.data(), key_base64.size());
        if (!bio) {
            cerr << "Error: Failed to create BIO for key decoding." << endl;
            return nullptr;
        }

        RSA *rsa_key = PEM_read_bio_RSA_PUBKEY(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);

        if (!rsa_key) {
            cerr << "Error: Failed to load RSA public key." << endl;
        }

        return rsa_key;
    }

    string base64_encode(const unsigned char *data, size_t length) {
        BIO *bio, *b64;
        BUF_MEM *bufferPtr;

        b64 = BIO_new(BIO_f_base64());
        bio = BIO_new(BIO_s_mem());
        bio = BIO_push(b64, bio);

        BIO_write(bio, data, length);
        BIO_flush(bio);
        BIO_get_mem_ptr(bio, &bufferPtr);

        string encoded(bufferPtr->data, bufferPtr->length - 1);
        BIO_free_all(bio);

        return encoded;
    }

    string fwso_api::encrypt_RSA(string raw) {
        RSA *rsa_key = load_public_key();
        if (!rsa_key) {
            throw runtime_error("Failed to load RSA public key.");
        }

        size_t key_size = RSA_size(rsa_key);
        size_t max_size = key_size - 2 * SHA256_DIGEST_LENGTH - 2; // OAEP overhead
        if (raw.size() > max_size) {
            cerr << "Error: RSA input exceeds allowed size. Truncating..." << endl;
            raw = raw.substr(0, max_size);
        }

        vector<unsigned char> encrypted_data(key_size);
        EVP_PKEY *pkey = EVP_PKEY_new();
        EVP_PKEY_assign_RSA(pkey, rsa_key);

        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, nullptr);
        if (!ctx) {
            cerr << "EVP_PKEY_CTX_new failed" << endl;
            throw runtime_error("Encryption context failed.");
        }

        if (EVP_PKEY_encrypt_init(ctx) <= 0 ||
            EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0 ||
            EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0 ||
            EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0) {
            cerr << "EVP_PKEY_CTX configuration failed" << endl;
            throw runtime_error("Encryption configuration failed.");
        }

        size_t outlen = encrypted_data.size();
        if (EVP_PKEY_encrypt(ctx, encrypted_data.data(), &outlen,
                             reinterpret_cast<const unsigned char *>(raw.c_str()), raw.size()) <= 0) {
            cerr << "EVP_PKEY_encrypt failed" << endl;
            throw runtime_error("RSA encryption failed.");
        }

        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);

        return base64_encode(encrypted_data.data(), outlen);
    }

    void fwso_api::create_AES() {
        aes_key_id = create_secure_AES_key();
        if (aes_key_id == -1)
            perror("Failed to initialize secure key.");
    }

    string fwso_api::decrypt_AES(const string &ciphertext) {
        try {
            // Retrieve AES key from keyring
            vector<unsigned char> aes_key = get_secure_AES_key(aes_key_id);
            if (aes_key.empty()) {
                throw runtime_error("AES key retrieval failed");
            }

            // Decode Base64 ciphertext
            string encrypted_data = utils::base64_decode(ciphertext);
            if (encrypted_data.size() < AES_BLOCK_SIZE) {
                throw runtime_error("Invalid encrypted data (too short)");
            }

            // Extract IV (first 16 bytes)
            unsigned char iv[AES_BLOCK_SIZE];
            memcpy(iv, encrypted_data.data(), AES_BLOCK_SIZE);

            // Extract actual encrypted message
            vector<unsigned char> encrypted_msg(encrypted_data.begin() + AES_BLOCK_SIZE, encrypted_data.end());

            if (encrypted_msg.size() % AES_BLOCK_SIZE != 0) {
                throw runtime_error("Ciphertext length is not a multiple of AES block size");
            }

            // Prepare output buffer
            vector<unsigned char> decrypted_msg(encrypted_msg.size());

            // Initialize AES context
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            if (!ctx) throw runtime_error("Failed to create AES context");

            if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, aes_key.data(), iv) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                throw runtime_error("AES decryption initialization failed");
            }

            int out_len1 = 0;
            if (EVP_DecryptUpdate(ctx, decrypted_msg.data(), &out_len1, encrypted_msg.data(), encrypted_msg.size()) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                throw runtime_error("AES decryption failed");
            }

            int out_len2 = 0;
            if (EVP_DecryptFinal_ex(ctx, decrypted_msg.data() + out_len1, &out_len2) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                throw runtime_error("AES padding validation failed - Possible incorrect key or data corruption");
            }

            EVP_CIPHER_CTX_free(ctx);

            // Resize decrypted message to actual size
            decrypted_msg.resize(out_len1 + out_len2);
            return string(decrypted_msg.begin(), decrypted_msg.end());

        } catch (const exception &e) {
            cerr << "Error: " << e.what() << endl;
            return "";
        }
    }

    key_serial_t fwso_api::store_secure_session_token(vector<unsigned char>& bytes) {
        key_serial_t key_id = add_key("user", AES_KEYRING_NAME, bytes.data(), SESSION_TOKEN_SIZE,
                                      KEY_SPEC_SESSION_KEYRING);
        if (key_id == -1) {
            perror("Failed to store AES key in keyring");
        } else {
            log_queue.emplace("AES key securely stored in kernel keyring.");
        }

        // Securely erase local key copy
        while (!bytes.empty()) {
            bytes[bytes.size()-1]=0;
            bytes.pop_back();
        }

        return key_id;
    }

    void fwso_api::remove_secure_session_token(key_serial_t key_id) {
        if (keyctl(KEYCTL_INVALIDATE, key_id, 0, 0, 0) == -1) {
            perror("Failed to remove AES key from keyring");
        } else {
            log_queue.emplace("AES key removed from keyring.");
        }
    }

    vector<unsigned char> fwso_api::get_secure_session_token(key_serial_t key_id) {
        vector<unsigned char> token(SESSION_TOKEN_SIZE);

        if (const ssize_t len = keyctl(KEYCTL_READ, key_id, token.data(), SESSION_TOKEN_SIZE, 0); len == -1) {
            perror("Failed to retrieve AES key from keyring");
            return {};
        }

        return token;
    }
}