#ifndef RSACRYPTO_H
#define RSACRYPTO_H

#include <openssl/crypto.h>
#include <vector>
#include <cstdint>

class RSA_Crypto {
public:
    RSA_Crypto();
    ~RSA_Crypto();

    RSA_Crypto(const RSA_Crypto &) = default;
    RSA_Crypto &operator=(const RSA_Crypto &) = default;
    RSA_Crypto(RSA_Crypto &&) = default;
    RSA_Crypto &operator=(RSA_Crypto &&) = default;

    EVP_PKEY* get_key() const;

    std::vector<uint8_t> sign(const std::vector<uint8_t>& data);
    bool verify(const std::vector<uint8_t>& data, const std::vector<uint8_t>& signature);
private:
    EVP_PKEY* _key {nullptr};

    void generate_key();
    static void handle_errors();
};


#endif //RSACRYPTO_H
