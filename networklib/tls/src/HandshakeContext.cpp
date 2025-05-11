#include "HandshakeContext.h"
#include "RSAPublicKey.h"
#include <AESCustom.h>

HandshakeContext::HandshakeContext(bool isClient) : _isClient(isClient), _handshakeComplete(false)
{
    if (!_isClient)
    {
        generateRSAKeyPair(static_cast<uint32_t>(RSACustom::RSAKeyLength::RSA_2048));
    }
}

void HandshakeContext::reset()
{
    _handshakeComplete = false;
    _sessionKey.clear();
}

bool HandshakeContext::isHandshakeComplete() const
{
    return _handshakeComplete;
}

void HandshakeContext::generateRSAKeyPair(const uint32_t& keySize)
{
    _rsa.generateKeys(keySize);
}

RSAPublicKey HandshakeContext::getPublicKey() const
{
    return _rsa.getPublicKey();
}

void HandshakeContext::generateSessionKey()
{
    _sessionKey = AESCustom::generateRandomKey(CIPHER_256_KEY_SIZE);
}

boost::multiprecision::cpp_int HandshakeContext::encryptSessionKeyWithServerRSA(const RSAPublicKey& serverPubKey) const
{
    if (!_isClient || _sessionKey.empty())
    {
        throw std::runtime_error("Session key not initialized");
    }
    return RSACustom::encrypt(_sessionKey, serverPubKey);
}

void HandshakeContext::decryptSessionKeyFromClient(const bmp::cpp_int& encryptedKey)
{
    if (_isClient)
    {
        throw std::runtime_error("Only server can decrypt");
    }
    _sessionKey = _rsa.decrypt(encryptedKey);
    _handshakeComplete = true;
}

const std::vector<uint8_t>& HandshakeContext::getSessionKey() const
{
    return _sessionKey;
}