#ifndef HANDSHAKEMANAGER_H
#define HANDSHAKEMANAGER_H

#include <cstdint>
#include <vector>
#include <TLSRecordLayer.h>
#include <ECDHECrypto.h>
#include <boost/asio/ip/tcp.hpp>

using btcp = boost::asio::ip::tcp;

class HandshakeManager
{
public:
    HandshakeManager(TLSRecordLayer& record, const std::vector<uint8_t>& psk = {}) : record_(record), psk_(psk) {}

    void do_client_handshake();

private:
    std::vector<uint8_t> transcript_hash() const;

    btcp::socket& socket_;
    TLSRecordLayer& record_;
    ECDHECrypto dhe_;
    std::vector<uint8_t> psk_, early_secret_, handshake_secret_, master_secret_, transcript_;
};

#endif  // HANDSHAKEMANAGER_H
