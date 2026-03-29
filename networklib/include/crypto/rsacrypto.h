#ifndef RSACRYPTO_H
#define RSACRYPTO_H

#include <cstdint>
#include <openssl/evp.h>
#include <vector>

class RSACrypto
{
public:
    RSACrypto();
    ~RSACrypto();

    RSACrypto(const RSACrypto&) = delete;
    RSACrypto& operator=(const RSACrypto&) = delete;
    RSACrypto(RSACrypto&& other) noexcept;
    RSACrypto& operator=(RSACrypto&& other) noexcept;

    EVP_PKEY* getKey() const;

    std::vector<uint8_t> sign(const std::vector<uint8_t>& data);
    bool verify(const std::vector<uint8_t>& data, const std::vector<uint8_t>& signature);

private:
    EVP_PKEY* _key{nullptr};

    void generateKey();
    static void handleErrors();
};

#endif  // RSACRYPTO_H
