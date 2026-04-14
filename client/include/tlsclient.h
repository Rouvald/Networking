#ifndef TLSCLIENT_H
#define TLSCLIENT_H

#include "crypto/ecdhecrypto.h"
#include "crypto/rsacrypto.h"
#include "utils/types.h"
#include <boost/asio/ip/tcp.hpp>
#include <cstdint>
#include <string>
class TLSClient
{
public:
    TLSClient(boost::asio::io_context& ioContext, const std::string& host, uint16_t port);
    ~TLSClient() = default;

    TLSClient(const TLSClient&) = default;
    TLSClient& operator=(const TLSClient&) = default;
    TLSClient(TLSClient&&) = default;
    TLSClient& operator=(TLSClient&&) noexcept = default;

    void runHandshakeAndSend();

private:
    btcp::socket _socket;
    RSACrypto _rsa;
    ECDHECrypto _clientEcdh;

    types::debug::Timer _timer;
};

#endif  // TLSCLIENT_H
