#ifndef HANDSHAKEMANAGER_H
#define HANDSHAKEMANAGER_H

#include <cstdint>
#include <vector>
#include "network/tlsrecordlayer.h"
#include "crypto/ecdhecrypto.h"

class HandshakeManager
{
public:
    HandshakeManager(btcp::socket& socket, TLSRecordLayer& record, const std::vector<uint8_t>& psk = {})
        : _socket(socket), _record(record), _psk(psk)
    {}

    void doClientHandshake();

private:
    std::vector<uint8_t> transcriptHash() const;

    btcp::socket& _socket;
    TLSRecordLayer& _record;
    ECDHECrypto _ecdhe;
    std::vector<uint8_t> _psk, _earlySecret, _handshakeSecret, _masterSecret, _transcript;
};

#endif  // HANDSHAKEMANAGER_H
