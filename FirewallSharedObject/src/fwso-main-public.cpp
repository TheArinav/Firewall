#include "fwso-main.hpp"

#include <sys/un.h>
#include <unistd.h>
#include <filesystem>
#include <fstream>
#include <algorithm>
#include <vector>
#include <openssl/bio.h>
#include <openssl/aes.h>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <string>
#include <unordered_set>

#include "structs/fw-message.hpp"
#include "utils.hpp"

char fwso::api::AES_KEYRING_NAME[64];
char fwso::api::ST_KEYRING_NAME[64];

namespace fwso::api {
    fwso_api::fwso_api() {
        snprintf(AES_KEYRING_NAME, sizeof(AES_KEYRING_NAME), AES_KEYRING_NAME_BASE, getpid());
        snprintf(ST_KEYRING_NAME, sizeof(ST_KEYRING_NAME), ST_KEYRING_NAME_BASE, getpid());
        log_queue = {};
        aes_key_id = {};
        sockfd = -1;
        firewall_service_pid = -1;
        create_AES();
        init();
        sockfd = uds_connect();
    }

    /**
     * Example function to use the AES key from keyring during communication.
     */
    int fwso_api::fw_connect(long int id, const string &key, string &resp_out) {
        long int pid = getpid();
        structs::message init_message = structs::message(
                structs::message_type::INIT,
                pid,
                firewall_service_pid
        );

        vector<unsigned char> aes_key = get_secure_AES_key(aes_key_id);
        if (aes_key.empty()) {
            perror("Failed to retrieve AES key.");
            return 1;
        }

        ostringstream hex_key_stream;
        for (auto byte : aes_key)
            hex_key_stream << hex << setw(2) << setfill('0') << static_cast<int>(byte);

        // Generate Nonce and Timestamp
        string nonce = utils::generate_nonce();
        long timestamp = time(nullptr);

        // Create the secure payload
        stringstream ss;
        ss << nonce << "|" << timestamp << "|"
           << hex_key_stream.str() << ":("
           << utils::format_uid_hex(id)
           << ",'" << key << "')";

        // Encrypt payload
        init_message.content = encrypt_RSA(ss.str());

        string response;
        send_message(init_message.to_string(), response);

        if (response.empty()) {
            cerr << "Error: No response received from server." << endl;
            return 2;
        }

        size_t last_comma = response.rfind(',');
        if (last_comma == string::npos) {
            cerr << "Error: Malformed response format (missing comma)." << endl;
            return 3;
        }

        string encrypted_data = response.substr(last_comma + 1);

        encrypted_data.erase(remove_if(encrypted_data.begin(), encrypted_data.end(), ::isspace), encrypted_data.end());
        if (!encrypted_data.empty() && encrypted_data.back() == '}') {
            encrypted_data.pop_back();
        }

        // Decrypt only the extracted part
        string decrypted_response = decrypt_AES(encrypted_data);

        // Remove outer curly braces if present
	if (!decrypted_response.empty() && decrypted_response.front() == '{' && decrypted_response.back() == '}') {
    		decrypted_response = decrypted_response.substr(1, decrypted_response.size() - 2);
	}

	// Find the last comma (which separates the timestamp)
        last_comma = decrypted_response.rfind(',');
	if (last_comma == string::npos) {
    		cerr << "Error: Invalid response format (missing last comma)." << endl;
    		return 4;
	}

	// Find the second last comma (which separates the nonce)
	size_t second_last_comma = decrypted_response.rfind(',', last_comma - 1);
	if (second_last_comma == string::npos) {
    		cerr << "Error: Invalid response format (missing second last comma)." << endl;
    		return 4;
	}

	// Extract the timestamp (last field)
	string timestamp_str = decrypted_response.substr(last_comma + 1);
	long received_timestamp = stol(timestamp_str);

	// Extract the nonce (second last field)
	string received_nonce = decrypted_response.substr(second_last_comma + 1, last_comma - second_last_comma - 1);

	// Everything before the second last comma is considered the actual content
	string actual_content = decrypted_response.substr(0, second_last_comma);
        // Validate timestamp (Replay Protection)
        long current_time = time(nullptr);
        const long TIMESTAMP_TOLERANCE = 30; // 30 seconds window
        if (abs(current_time - received_timestamp) > TIMESTAMP_TOLERANCE) {
            cerr << "Error: Response timestamp is out of valid range!" << endl;
            return 5;
        }

        // Validate nonce (Prevent replay attacks)
        static unordered_set<string> used_nonces;
        if (used_nonces.find(received_nonce) != used_nonces.end()) {
            cerr << "Error: Duplicate nonce detected (Replay attack prevention)." << endl;
            return 6;
        }
        used_nonces.insert(received_nonce);

        // Decode actual content
        auto first_comma = actual_content.find(',');
        string result = actual_content.substr(0,first_comma);
        actual_content = actual_content.substr(first_comma+2);
        first_comma = actual_content.find(',');
        actual_content = actual_content.substr(0,first_comma-1);
        auto divider = actual_content.find('|');
        string message = actual_content.substr(0,divider);
        string encoded_session_token = actual_content.substr(divider+1);

        resp_out = message;
        if (encoded_session_token == "null")
            return 101;

        else if (result != "True")
            return 100;

        auto decoded_session_token = base64_decode(encoded_session_token);
        store_secure_session_token(decoded_session_token);

        while(!decoded_session_token.empty()){
            decoded_session_token[decoded_session_token.size()-1] = 0;
            decoded_session_token.pop_back();
        }

        return 0;
    }

    fwso_api::~fwso_api() {
        // Clean up the socket if it's open.
        if (sockfd != -1) {
            close(sockfd);
        }
        // Remove the AES key from the keyring if it was created.
        if (aes_key_id != -1) {
            remove_secure_AES_key(aes_key_id);
        }
        // Remove the session token from the keyring if it was created.
        if (st_key_id != -1) {
            remove_secure_session_token(st_key_id);
        }
    }
}

extern "C" {

    fwso::api::fwso_api* create_fwso_instance() {
        return new fwso::api::fwso_api();
    }

    void destroy_fwso_instance(fwso::api::fwso_api* instance) {
        delete instance;
    }

    int fw_connect(fwso::api::fwso_api* instance, long int id, const char* key, char* out_resp, size_t out_size) {
        std::string resp;
        int result = instance->fw_connect(id, std::string(key), resp);
        // Copy response to the output buffer
        strncpy(out_resp, resp.c_str(), out_size);
        // Ensure null termination
        out_resp[out_size - 1] = '\0';
        return result;
    }
}