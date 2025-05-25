#ifndef TLSCLIENT_H
#define TLSCLIENT_H

#include <boost/asio.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <RSACrypto.h>
#include <ECDHECrypto.h>
#include <string>
#include <cstdint>
#include <openssl/crypto.h>
#include <vector>

using btcp = boost::asio::ip::tcp;

class TLSClient
{
public:
    TLSClient(boost::asio::io_context& io_context, const std::string& host, uint16_t port);
    ~TLSClient() = default;

    TLSClient(const TLSClient &) = default;
    TLSClient &operator=(const TLSClient &) = default;
    TLSClient(TLSClient &&) = default;
    TLSClient &operator=(TLSClient &&) = default;

private:
    btcp::socket _socket;
    RSA_Crypto _rsa;
    ECDHE_Crypto _client_ecdh;

    void run_handshake_and_send();
    static uint32_t read_uint32(btcp::socket& socket);
    static void write_uint32(btcp::socket& socket, uint32_t val);
    static EVP_PKEY* d2i_PUBKEY_from_vector(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> sha256(const std::vector<uint8_t>& input);
};

#endif  // TLSCLIENT_H
