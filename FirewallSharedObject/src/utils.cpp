#include "utils.hpp"

#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <sstream>
#include <iomanip>
#include <vector>

namespace fwso::utils {

     string format_pid_hex(long int pid) {
        ostringstream oss = {};
        oss << uppercase
            << setw(6)
            << setfill('0')
            << hex
            << pid;
        return oss.str();
    }

    string format_uid_hex(long int uid){
         ostringstream oss = {};
         oss << uppercase
             << setw(16)
             << setfill('0')
             << hex
             << uid;
         return oss.str();
     }


    string base64_encode(const unsigned char* data, size_t length) {
         BIO* bio, * b64;
         BUF_MEM* bufferPtr;

         b64 = BIO_new(BIO_f_base64());
         bio = BIO_new(BIO_s_mem());
         bio = BIO_push(b64, bio);
         BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // No newlines in output

         BIO_write(bio, data, length);
         BIO_flush(bio);
         BIO_get_mem_ptr(bio, &bufferPtr);

         std::string encoded(bufferPtr->data, bufferPtr->length);
         BIO_free_all(bio);
         return encoded;
     }

    string generate_nonce() {
         unsigned char nonce_bytes[16];

         if (RAND_bytes(nonce_bytes, sizeof(nonce_bytes)) != 1)
             return "";

         return base64_encode(nonce_bytes, sizeof(nonce_bytes));
     }

    string base64_decode(const string &encoded) {
         BIO *bio, *b64;
         int decodeLen = encoded.size();
         vector<unsigned char> buffer(decodeLen);

         bio = BIO_new_mem_buf(encoded.data(), encoded.size());
         b64 = BIO_new(BIO_f_base64());
         bio = BIO_push(b64, bio);
         BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // No newlines

         int len = BIO_read(bio, buffer.data(), decodeLen);
         BIO_free_all(bio);

         return string(reinterpret_cast<char*>(buffer.data()), len);
     }
}
