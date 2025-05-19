#ifndef RSACRYPTO_H
#define RSACRYPTO_H

#include <openssl/rsa.h>
#include <vector>
#include <cstdint>

class RSA_Crypto {
public:
    RSA_Crypto();
    ~RSA_Crypto();

    EVP_PKEY* get_key() const;

    std::vector<uint8_t> sign(const std::vector<uint8_t>& data);
    bool verify(const std::vector<uint8_t>& data, const std::vector<uint8_t>& signature);
private:
    EVP_PKEY* key = nullptr;

    void generate_key();
    static void handle_errors();
};


#endif //RSACRYPTO_H
