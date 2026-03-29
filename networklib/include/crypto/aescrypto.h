#ifndef AESCRYPTO_H
#define AESCRYPTO_H

#include <cstdint>
#include <vector>
#include "utils/types.h"

class AESCrypto
{
public:
    explicit AESCrypto(const std::vector<uint8_t>& key);
    ~AESCrypto() = default;

    AESCrypto(const AESCrypto&) = default;
    AESCrypto& operator=(const AESCrypto&) = default;
    AESCrypto(AESCrypto&&) = default;
    AESCrypto& operator=(AESCrypto&&) = default;

    static std::vector<uint8_t> generateIv();
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& ivKey, std::vector<uint8_t>& tag);
    std::vector<uint8_t> decrypt(
        const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& ivKey, const std::vector<uint8_t>& tag);

private:
    std::vector<uint8_t> _key;

    static void handleErrors();
};

#endif  // AESCRYPTO_H
