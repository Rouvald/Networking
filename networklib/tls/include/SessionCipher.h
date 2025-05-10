#ifndef SESSIONCIPHER_H
#define SESSIONCIPHER_H

#include <vector>
#include <cstdint>
#include "AESCustom.h"

class SessionCipher
{
public:
    SessionCipher();
    void setKey(const std::vector<uint8_t>& key);
    void setIV(const std::vector<uint8_t>& ivKey);
    const std::vector<uint8_t>& getIV() const;

    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& data) const;
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& encrypted) const;

private:
    std::vector<uint8_t> _key;
    std::vector<uint8_t> _iv;
    AESKeyLength _aesLen;
    bool _keySet{false};
};

#endif  // SESSIONCIPHER_H
