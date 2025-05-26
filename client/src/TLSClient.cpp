#include "TLSClient.h"
#include <AESCrypto.h>
#include <UtilsCrypto.h>
#include <boost/asio.hpp>
#include <cstdint>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <string>
#include <vector>

TLSClient::TLSClient(boost::asio::io_context& io_context, const std::string& host, uint16_t port) : _socket(io_context)
{
    btcp::resolver resolver(io_context);
    boost::asio::connect(_socket, resolver.resolve(host, std::to_string(port)));
}

void TLSClient::run_handshake_and_send()
{
    std::vector<uint8_t> client_pub{_client_ecdh.get_public_key_der()};
    UtilsNetwork::write_uint32(_socket, client_pub.size());
    boost::asio::write(_socket, boost::asio::buffer(client_pub));

    const uint32_t server_pub_len{UtilsNetwork::read_uint32(_socket)};
    std::vector<uint8_t> server_pub(server_pub_len);
    boost::asio::read(_socket, boost::asio::buffer(server_pub));

    EVP_PKEY* server_key{UtilsCrypto::d2i_PUBKEY_from_vector(server_pub)};
    const std::vector<uint8_t> shared_secret{_client_ecdh.compute_shared_secret(server_key)};
    EVP_PKEY_free(server_key);
    auto aes_key{UtilsCrypto::sha256(shared_secret)};

    AESCrypto aes(aes_key);

    const std::string msg{"Hello from server! Add some useless info for testing"};
    std::vector<uint8_t> ivKey{AESCrypto::generate_iv()};
    std::vector<uint8_t> tag;
    std::vector<uint8_t> ciphertext{aes.encrypt(std::vector<uint8_t>(msg.begin(), msg.end()), ivKey, tag)};

    boost::asio::write(_socket, boost::asio::buffer(ivKey));

    boost::asio::write(_socket, boost::asio::buffer(tag));

    UtilsNetwork::write_uint32(_socket, ciphertext.size());
    boost::asio::write(_socket, boost::asio::buffer(ciphertext));

    std::cout << "Encrypted message sent to server." << '\n';
}
