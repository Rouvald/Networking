#ifndef ECDHECRYPTO_H
#define ECDHECRYPTO_H

#include <cstdint>
#include <openssl/evp.h>
#include <vector>

class ECDHECrypto
{
public:
    ECDHECrypto();
    ~ECDHECrypto();

    ECDHECrypto(const ECDHECrypto&) = default;
    ECDHECrypto& operator=(const ECDHECrypto&) = default;
    ECDHECrypto(ECDHECrypto&&) = default;
    ECDHECrypto& operator=(ECDHECrypto&&) = default;

    EVP_PKEY* get_key() const;
    std::vector<uint8_t> get_public_key_der() const;
    std::vector<uint8_t> compute_shared_secret(EVP_PKEY* peer_key) const;

private:
    EVP_PKEY* _key{nullptr};

    void generate_key();
};

#endif  // ECDHECRYPTO_H
