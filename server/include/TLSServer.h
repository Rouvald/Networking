#ifndef TLSSERVER_H
#define TLSSERVER_H

#include <boost/asio.hpp>
#include <RSACrypto.h>
#include <ECDHECrypto.h>

using boost::asio::ip::tcp;

class TLSServer
{
public:
    TLSServer(boost::asio::io_context& io_context, tcp::endpoint endpoint);

private:
    tcp::acceptor acceptor;
    RSA_Crypto rsa;
    ECDHE_Crypto server_ecdh;

    void start_accept();
    void handle_handshake(tcp::socket& socket);
    uint32_t read_uint32(tcp::socket& socket);
    void write_uint32(tcp::socket& socket, uint32_t val);
    EVP_PKEY* d2i_PUBKEY_from_vector(const std::vector<uint8_t>& data);
    std::vector<uint8_t> sha256(const std::vector<uint8_t>& input);
};

#endif  // TLSSERVER_H
