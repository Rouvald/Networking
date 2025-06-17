#ifndef RSACRYPTO_H
#define RSACRYPTO_H

#include <cstdint>
#include <openssl/crypto.h>
#include <vector>

class RSACrypto
{
public:
    RSACrypto();
    ~RSACrypto();

    RSACrypto(const RSACrypto&) = default;
    RSACrypto& operator=(const RSACrypto&) = default;
    RSACrypto(RSACrypto&&) = default;
    RSACrypto& operator=(RSACrypto&&) = default;

    EVP_PKEY* get_key() const;

    std::vector<uint8_t> sign(const std::vector<uint8_t>& data);
    bool verify(const std::vector<uint8_t>& data, const std::vector<uint8_t>& signature);

private:
    EVP_PKEY* _key{nullptr};

    void generate_key();
    static void handle_errors();
};

#endif  // RSACRYPTO_H
