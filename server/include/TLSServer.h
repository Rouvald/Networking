#ifndef TLSSERVER_H
#define TLSSERVER_H

#include <RSACrypto.h>
#include <ECDHECrypto.h>
#include <UtilsNetwork.h>
#include <boost/asio.hpp>
#include <boost/asio/ip/tcp.hpp>

class TLSServer
{
public:
    TLSServer(boost::asio::io_context& io_context, const btcp::endpoint& endpoint);
    void start_accept();

private:
    btcp::acceptor _acceptor;
    RSACrypto _rsa;
    ECDHECrypto _server_ecdh;

    Timer::Timer _timer;

    void handle_handshake(btcp::socket& socket);
};

#endif  // TLSSERVER_H
