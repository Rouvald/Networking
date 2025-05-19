#ifndef ECDHECRYPTO_H
#define ECDHECRYPTO_H

#include <openssl/evp.h>
#include <vector>

class ECDHE_Crypto {
public:
    ECDHE_Crypto();
    ~ECDHE_Crypto();

    EVP_PKEY* get_key() const ;
    std::vector<uint8_t> get_public_key_der() const;
    std::vector<uint8_t> compute_shared_secret(EVP_PKEY* peer_key) const ;

private:
    EVP_PKEY* key = nullptr;

    void generate_key();
};

#endif //ECDHECRYPTO_H
