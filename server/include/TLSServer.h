#ifndef TLSSERVER_H
#define TLSSERVER_H

#include <RSACrypto.h>
#include <ECDHECrypto.h>
#include <boost/asio.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <cstdint>
#include <openssl/crypto.h>
#include <vector>

using btcp = boost::asio::ip::tcp;

class TLSServer
{
public:
    TLSServer(boost::asio::io_context& io_context, const btcp::endpoint& endpoint);

private:
    btcp::acceptor _acceptor;
    RSA_Crypto _rsa;
    ECDHE_Crypto _server_ecdh;

    void start_accept();
    void handle_handshake(btcp::socket& socket);
    uint32_t read_uint32(btcp::socket& socket);
    void write_uint32(btcp::socket& socket, uint32_t val);
    EVP_PKEY* d2i_PUBKEY_from_vector(const std::vector<uint8_t>& data);
    std::vector<uint8_t> sha256(const std::vector<uint8_t>& input);
};

#endif  // TLSSERVER_H
