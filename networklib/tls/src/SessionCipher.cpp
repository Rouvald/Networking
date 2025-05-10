#include "AESCustom.h"
#include "SessionCipher.h"
#include <cstdint>
#include <stdexcept>
#include <vector>

SessionCipher::SessionCipher() : _aesLen(AESKeyLength::AES_128)  // @note: def
{
}

void SessionCipher::setKey(const std::vector<uint8_t>& key)
{
    _key = key;
    if (key.size() == CIPHER_128_KEY_SIZE)
    {
        _aesLen = AESKeyLength::AES_128;
    }
    else if (key.size() == CIPHER_256_KEY_SIZE)
    {
        _aesLen = AESKeyLength::AES_256;
    }
    else
    {
        throw std::invalid_argument("Unsupported AES key size");
    }
    _keySet = true;

    if (_iv.empty())
    {
        _iv = AESCustom::generateRandomIV();  // @noter: def
    }
}

void SessionCipher::setIV(const std::vector<uint8_t>& ivKey)
{
    if (ivKey.size() != CIPHER_IV_SIZE)
    {
        throw std::invalid_argument("IV must be 16 bytes");
    }
    _iv = ivKey;
}

const std::vector<uint8_t>& SessionCipher::getIV() const
{
    return _iv;
}

std::vector<uint8_t> SessionCipher::encrypt(const std::vector<uint8_t>& data) const
{
    if (!_keySet)
    {
        throw std::runtime_error("Key not set");
    }
    AESCustom aes(_aesLen);
    return aes.EncryptCBC(data, _key, _iv);
}

std::vector<uint8_t> SessionCipher::decrypt(const std::vector<uint8_t>& encrypted) const
{
    if (!_keySet)
    {
        throw std::runtime_error("Key not set");
    }
    AESCustom aes(_aesLen);
    return aes.DecryptCBC(encrypted, _key, _iv);
}
