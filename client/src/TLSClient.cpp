#include "TLSClient.h"
#include <iostream>
#include <AESCrypto.h>

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/x509.h>

constexpr uint8_t SHA256_KEY_SIZE{32};

TLSClient::TLSClient(boost::asio::io_context& io_context, const std::string& host, uint16_t port) : _socket(io_context)
{
    btcp::resolver resolver(io_context);
    boost::asio::connect(_socket, resolver.resolve(host, std::to_string(port)));
    std::cout << "Connected to client." << std::endl;

    run_handshake_and_send();
}

void TLSClient::run_handshake_and_send()
{
    std::vector<uint8_t> client_pub = _client_ecdh.get_public_key_der();
    write_uint32(_socket, client_pub.size());
    boost::asio::write(_socket, boost::asio::buffer(client_pub));

    const uint32_t server_pub_len = read_uint32(_socket);
    std::vector<uint8_t> server_pub(server_pub_len);
    boost::asio::read(_socket, boost::asio::buffer(server_pub));

    EVP_PKEY* server_key = d2i_PUBKEY_from_vector(server_pub);
    const std::vector<uint8_t> shared_secret = _client_ecdh.compute_shared_secret(server_key);
    EVP_PKEY_free(server_key);
    auto aes_key = sha256(shared_secret);

    AES_Crypto aes(aes_key);

    std::string msg = "Hello from server!";
    std::vector<uint8_t> ivKey = aes.generate_iv();
    std::vector<uint8_t> tag;
    std::vector<uint8_t> ciphertext = aes.encrypt(std::vector<uint8_t>(msg.begin(), msg.end()), ivKey, tag);

    boost::asio::write(_socket, boost::asio::buffer(ivKey));

    boost::asio::write(_socket, boost::asio::buffer(tag));

    write_uint32(_socket, ciphertext.size());
    boost::asio::write(_socket, boost::asio::buffer(ciphertext));

    std::cout << "Encrypted message sent to client." << '\n';
}

uint32_t TLSClient::read_uint32(btcp::socket& socket)
{
    uint32_t val{0};
    boost::asio::read(socket, boost::asio::buffer(&val, sizeof(val)));
    return ntohl(val);
}

void TLSClient::write_uint32(btcp::socket& socket, uint32_t val)
{
    uint32_t net_val = htonl(val);
    boost::asio::write(socket, boost::asio::buffer(&net_val, sizeof(net_val)));
}

EVP_PKEY* TLSClient::d2i_PUBKEY_from_vector(const std::vector<uint8_t>& data)
{
    const unsigned char* ptr = data.data();
    return d2i_PUBKEY(nullptr, &ptr, static_cast<long>(data.size()));
}

std::vector<uint8_t> TLSClient::sha256(const std::vector<uint8_t>& input)
{
    std::vector<uint8_t> output(SHA256_KEY_SIZE);
    SHA256(input.data(), input.size(), output.data());
    return output;
}
