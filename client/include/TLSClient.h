#ifndef TLSCLIENT_H
#define TLSCLIENT_H

#include <ECDHECrypto.h>
#include <RSACrypto.h>
#include <UtilsNetwork.h>
#include <boost/asio/ip/tcp.hpp>
#include <cstdint>
#include <string>

using btcp = boost::asio::ip::tcp;

class TLSClient
{
public:
    TLSClient(boost::asio::io_context& io_context, const std::string& host, uint16_t port);
    ~TLSClient() = default;

    TLSClient(const TLSClient&) = default;
    TLSClient& operator=(const TLSClient&) = default;
    TLSClient(TLSClient&&) = default;
    TLSClient& operator=(TLSClient&&) noexcept = default;

    void run_handshake_and_send();

private:
    btcp::socket _socket;
    RSACrypto _rsa;
    ECDHECrypto _client_ecdh;

    Timer::Timer _timer;
};

#endif  // TLSCLIENT_H
