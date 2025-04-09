#pragma once

#ifndef FWSO_MAIN_HPP
#define FWSO_MAIN_HPP

#include <string>
#include <queue>
#include <vector>
#include <keyutils.h>
#include <cstring>

#define AES_KEY_SIZE 32

using namespace std;

namespace fwso::api {

#define FIREWALL_SERVICE_NAME "FirewallService"
#define AES_KEY_SIZE 32
#define AES_KEYRING_NAME_BASE "firewall_aes_key_%d"
#define SESSION_TOKEN_SIZE 32
#define ST_KEYRING_NAME_BASE "firewall_session_token_%d"

    extern char AES_KEYRING_NAME[64];
    extern char ST_KEYRING_NAME[64];

    vector<unsigned char> base64_decode(const string &encoded);

    class fwso_api {
    private:
        key_serial_t aes_key_id;
        key_serial_t st_key_id;
        int sockfd;

        void init();

        int uds_connect();

        void create_AES();
        key_serial_t create_secure_AES_key();
        void remove_secure_AES_key(key_serial_t key_id);
        static vector<unsigned char> get_secure_AES_key(key_serial_t key_id);

        key_serial_t store_secure_session_token(vector<unsigned char>& bytes);
        void remove_secure_session_token(key_serial_t key_id);
        static vector<unsigned char> get_secure_session_token(key_serial_t  key_id);
        string encrypt_RSA(string raw);

        string decrypt_AES(const string &ct);
        string encrypt_AES(const string &raw);

        void send_message(const string &message, string &resp);

    public:
        const string SOCKET_PATH = "/run/firewall_uds_epoll_server.sock";
        const string RSA_KEY_PATH = "/etc/firewall/public.key";
        long int firewall_service_pid;
        queue<string> log_queue;

        fwso_api();
        ~fwso_api();

        int fw_connect(long int id, const string &key, string &resp_out);
    };
}




#endif // Fixed: Removed extra label
