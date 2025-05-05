#ifndef HANDSHAKECONTEXT_H
#define HANDSHAKECONTEXT_H

#include <vector>
#include <cstdint>
#include <string>
#include "RSACustom.h"
#include "AESCustom.h"

class HandshakeContext {
public:
    explicit HandshakeContext(bool isClient);

    bool isHandshakeComplete() const;
    void reset();

    void generateSessionKey();
    boost::multiprecision::cpp_int encryptSessionKeyWithServerRSA(const RSAPublicKey& serverPubKey) const;

    void generateRSAKeyPair();
    RSAPublicKey getPublicKey() const;
    void decryptSessionKeyFromClient(const bmp::cpp_int& encryptedKey);

    const std::vector<uint8_t>& getSessionKey() const;

private:
    bool _isClient;
    bool _handshakeComplete;

    RSACustom _rsa;
    std::vector<uint8_t> _sessionKey;
};

#endif //HANDSHAKECONTEXT_H
