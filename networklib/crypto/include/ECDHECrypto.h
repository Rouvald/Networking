#ifndef ECDHECRYPTO_H
#define ECDHECRYPTO_H

#include <cstdint>
#include <openssl/evp.h>
#include <vector>

class ECDHE_Crypto {
public:
    ECDHE_Crypto();
    ~ECDHE_Crypto();

    ECDHE_Crypto(const ECDHE_Crypto &) = default;
    ECDHE_Crypto &operator=(const ECDHE_Crypto &) = default;
    ECDHE_Crypto(ECDHE_Crypto &&) = default;
    ECDHE_Crypto &operator=(ECDHE_Crypto &&) = default;

    EVP_PKEY* get_key() const ;
    std::vector<uint8_t> get_public_key_der() const;
    std::vector<uint8_t> compute_shared_secret(EVP_PKEY* peer_key) const ;

private:
    EVP_PKEY* _key {nullptr};

    void generate_key();
};

#endif //ECDHECRYPTO_H
