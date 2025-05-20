#ifndef TLSCLIENT_H
#define TLSCLIENT_H

#include <boost/asio.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <RSACrypto.h>
#include <ECDHECrypto.h>

using boost::asio::ip::tcp;

class TLSClient
{
public:
    TLSClient(boost::asio::io_context& io_context, const std::string& host, uint16_t port);

private:
    tcp::socket socket;
    RSA_Crypto rsa;
    ECDHE_Crypto client_ecdh;

    void run_handshake_and_send();
    uint32_t read_uint32(tcp::socket& socket);
    void write_uint32(tcp::socket& socket, uint32_t val);
    EVP_PKEY* d2i_PUBKEY_from_vector(const std::vector<uint8_t>& data);
    std::vector<uint8_t> sha256(const std::vector<uint8_t>& input);
};

#endif  // TLSCLIENT_H
