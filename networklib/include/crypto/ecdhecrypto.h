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

    EVP_PKEY* getKey() const;
    std::vector<uint8_t> getPublicKeyDer() const;
    std::vector<uint8_t> computeSharedSecret(EVP_PKEY* peerKey) const;

private:
    EVP_PKEY* _key{nullptr};

    void generateKey();
    static void handleErrors();
};

#endif  // ECDHECRYPTO_H
