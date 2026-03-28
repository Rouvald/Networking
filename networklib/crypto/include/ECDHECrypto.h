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

    ECDHECrypto(const ECDHECrypto&) = delete;
    ECDHECrypto& operator=(const ECDHECrypto&) = delete;
    ECDHECrypto(ECDHECrypto&& other) noexcept;
    ECDHECrypto& operator=(ECDHECrypto&& other) noexcept;

    EVP_PKEY* get_key() const;
    std::vector<uint8_t> get_public_key_der() const;
    std::vector<uint8_t> compute_shared_secret(EVP_PKEY* peer_key) const;

private:
    EVP_PKEY* _key{nullptr};

    void generate_key();
    static void handle_errors();
};

#endif  // ECDHECRYPTO_H
