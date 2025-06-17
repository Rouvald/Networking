#ifndef UTILSCRYPTO_H
#define UTILSCRYPTO_H

#include <cstdint>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <vector>

namespace UtilsCrypto
{
    constexpr uint8_t SHA256_KEY_SIZE{32};

    inline std::vector<uint8_t> sha256(const std::vector<uint8_t>& input)
    {
        std::vector<uint8_t> output(SHA256_KEY_SIZE);
        SHA256(input.data(), input.size(), output.data());
        return output;
    }
    inline EVP_PKEY* d2i_PUBKEY_from_vector(const std::vector<uint8_t>& data)
    {
        const uint8_t* ptr{data.data()};
        return d2i_PUBKEY(nullptr, &ptr, static_cast<long>(data.size()));
    }
    inline std::vector<uint8_t> hmac_sha256(const std::vector<uint8_t>& key, const std::vector<uint8_t>& data)
    {
        unsigned int len = EVP_MAX_MD_SIZE;
        std::vector<uint8_t> result(len);

        HMAC(EVP_sha256(),
            key.data(), key.size(),
            data.data(), data.size(),
            result.data(), &len);

        result.resize(len);
        return result;
    }
} // namespace UtilsCrypto

#endif  // UTILSCRYPTO_H