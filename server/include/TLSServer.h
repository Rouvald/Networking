#ifndef TLSSERVER_H
#define TLSSERVER_H

#include <RSACrypto.h>
#include <ECDHECrypto.h>
#include <UtilsNetwork.h>
#include <Utils.h>
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

    TLSServer(boost::asio::io_context& io_context, const btcp::endpoint& endpoint);

    void start_accept();

private:
    void handle_handshake(btcp::socket& socket);
    void process_client_hello(btcp::socket& socket);
    void send_server_hello(btcp::socket& socket);
    void process_client_finished(btcp::socket& socket);

    btcp::acceptor _acceptor;
    RSACrypto _rsa;
    ECDHECrypto _server_ecdh;
    Utils::Timer _timer;
    HandshakeState _handshake_state;
    std::vector<uint8_t> _client_public_key;
};

#endif  // TLSSERVER_H
