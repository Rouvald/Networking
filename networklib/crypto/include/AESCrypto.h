#ifndef AESCRYPTO_H
#define AESCRYPTO_H

#include <cstdint>
#include <vector>

constexpr uint8_t AES_KEY_SIZE{32};
constexpr uint8_t AES_IV_KEY_SIZE{12};

class AESCrypto
{
public:
    explicit AESCrypto(const std::vector<uint8_t>& key_);
    ~AESCrypto() = default;

    AESCrypto(const AESCrypto&) = default;
    AESCrypto& operator=(const AESCrypto&) = default;
    AESCrypto(AESCrypto&&) = default;
    AESCrypto& operator=(AESCrypto&&) = default;

    static std::vector<uint8_t> generate_iv();
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& ivKey, std::vector<uint8_t>& tag);
    std::vector<uint8_t> decrypt(
        const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& ivKey, const std::vector<uint8_t>& tag);

private:
    std::vector<uint8_t> _key;
};

#endif  // AESCRYPTO_H
