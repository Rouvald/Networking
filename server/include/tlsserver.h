#ifndef TLSSERVER_H
#define TLSSERVER_H

#include "crypto/rsacrypto.h"
#include "crypto/ecdhecrypto.h"
#include "utils/types.h"
#include <boost/asio.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ts/buffer.hpp>
#include <boost/asio/ts/internet.hpp>

using btcp = boost::asio::ip::tcp;

class TLSServer
{
public:
    enum class HandshakeState
    {
        IDLE,
        WAIT_CLIENT_HELLO,
        SEND_SERVER_HELLO,
        WAIT_CLIENT_FINISHED,
        HANDSHAKE_COMPLETE
    };

    TLSServer(boost::asio::io_context& ioContext, const btcp::endpoint& endpoint);

    void startAccept();

private:
    void handleHandshake(btcp::socket& socket);
    void processClientHello(btcp::socket& socket);
    void sendServerHello(btcp::socket& socket);
    void processClientFinished(btcp::socket& socket);

    btcp::acceptor _acceptor;
    RSACrypto _rsa;
    ECDHECrypto _serverEcdh;
    types::debug::Timer _timer;
    HandshakeState _handshakeState;
    std::vector<uint8_t> _clientPublicKey;
};

#endif  // TLSSERVER_H
