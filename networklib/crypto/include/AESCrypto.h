#ifndef AESCRYPTO_H
#define AESCRYPTO_H

#include <vector>
#include <cstdint>

constexpr uint8_t AES_KEY_SIZE {32};
constexpr uint8_t AES_IV_KEY_SIZE {12};

class AES_Crypto
{
public:
    explicit AES_Crypto(const std::vector<uint8_t>& key_);
    ~AES_Crypto() = default;

    AES_Crypto(const AES_Crypto &) = default;
    AES_Crypto &operator=(const AES_Crypto &) = default;
    AES_Crypto(AES_Crypto &&) = default;
    AES_Crypto &operator=(AES_Crypto &&) = default;

    static std::vector<uint8_t> generate_iv();
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& ivKey, std::vector<uint8_t>& tag);
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& ivKey, const std::vector<uint8_t>& tag);

private:
    std::vector<uint8_t> _key;
};

#endif  // AESCRYPTO_H
