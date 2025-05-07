#include "SessionCipher.h"

#include <stdexcept>

#include <iostream>

SessionCipher::SessionCipher() : _aesLen(AESKeyLength::AES_128)  // @note: def
{
}

void SessionCipher::setKey(const std::vector<uint8_t>& key)
{
    _key = key;
    _aesLen = (key.size() == 16)   ? AESKeyLength::AES_128
              : (key.size() == 32) ? AESKeyLength::AES_256
                                   : throw std::invalid_argument("Unsupported AES key size");
    _keySet = true;

    if (_iv.empty())
    {
        _iv = AESCustom::generateRandomIV();  // @noter: def
    }
}

void SessionCipher::setIV(const std::vector<uint8_t>& iv)
{
    if (iv.size() != 16)
    {
        throw std::invalid_argument("IV must be 16 bytes");
    }
    _iv = iv;
}

const std::vector<uint8_t>& SessionCipher::getIV() const
{
    return _iv;
}

std::vector<uint8_t> SessionCipher::encrypt(const std::vector<uint8_t>& data)
{
    if (!_keySet)
        throw std::runtime_error("Key not set");
    AESCustom aes(_aesLen);

    //std::cout << "key - " << _key << "\n iv - " << _iv << std::endl;
    //for (const auto& k : _key)

    return aes.EncryptCBC(data, _key, _iv);
}

std::vector<uint8_t> SessionCipher::decrypt(const std::vector<uint8_t>& encrypted)
{
    if (!_keySet)
        throw std::runtime_error("Key not set");
    AESCustom aes(_aesLen);
    return aes.DecryptCBC(encrypted, _key, _iv);
}
