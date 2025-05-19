#ifndef AESCRYPTO_H
#define AESCRYPTO_H

#include <vector>
#include <cstdint>

class AES_Crypto
{
public:
    AES_Crypto(const std::vector<uint8_t>& key_);
    std::vector<uint8_t> generate_iv();
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& iv, std::vector<uint8_t>& tag);
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& iv, const std::vector<uint8_t>& tag);

private:
    std::vector<uint8_t> key;
};

#endif  // AESCRYPTO_H
