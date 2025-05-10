#include "HandshakeContext.h"
#include "RSAPublicKey.h"
#include <AESCustom.h>

HandshakeContext::HandshakeContext(bool isClient) : _isClient(isClient), _handshakeComplete(false)
{
    if (!_isClient)
    {
        generateRSAKeyPair();
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

void HandshakeContext::generateRSAKeyPair()
{
    // @todo: mb need pass bits, like 1024, 2048
    _rsa.generateKeys();
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
    std::string sessionKeyStr(_sessionKey.begin(), _sessionKey.end());

    RSACustom tempRsa;
    tempRsa.loadPublicKey(serverPubKey);

    return tempRsa.encrypt(sessionKeyStr);
}

void HandshakeContext::decryptSessionKeyFromClient(const bmp::cpp_int& encryptedKey)
{
    if (_isClient)
    {
        throw std::runtime_error("Only server can decrypt");
    }
    std::string decryptedStr = _rsa.decrypt(encryptedKey);
    _sessionKey = std::vector<uint8_t>(decryptedStr.begin(), decryptedStr.end());
    _handshakeComplete = true;
}

const std::vector<uint8_t>& HandshakeContext::getSessionKey() const
{
    return _sessionKey;
}