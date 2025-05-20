#include "TLSClient.h"
#include <iostream>
#include <AESCrypto.h>

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/x509.h>

TLSClient::TLSClient(boost::asio::io_context& io_context, const std::string& host, uint16_t port) : socket(io_context)
{
    tcp::resolver resolver(io_context);
    boost::asio::connect(socket, resolver.resolve(host, std::to_string(port)));
    std::cout << "Connected to client." << std::endl;

    run_handshake_and_send();
}

void TLSClient::run_handshake_and_send()
{
    std::vector<uint8_t> client_pub = client_ecdh.get_public_key_der();
    write_uint32(socket, client_pub.size());
    boost::asio::write(socket, boost::asio::buffer(client_pub));

    uint32_t server_pub_len = read_uint32(socket);
    std::vector<uint8_t> server_pub(server_pub_len);
    boost::asio::read(socket, boost::asio::buffer(server_pub));

    EVP_PKEY* server_key = d2i_PUBKEY_from_vector(server_pub);
    std::vector<uint8_t> shared_secret = client_ecdh.compute_shared_secret(server_key);
    EVP_PKEY_free(server_key);
    auto aes_key = sha256(shared_secret);

    AES_Crypto aes(aes_key);

    std::string msg = "Hello from server!";
    std::vector<uint8_t> iv = aes.generate_iv();
    std::vector<uint8_t> tag;
    std::vector<uint8_t> ciphertext = aes.encrypt(std::vector<uint8_t>(msg.begin(), msg.end()), iv, tag);

    boost::asio::write(socket, boost::asio::buffer(iv));

    boost::asio::write(socket, boost::asio::buffer(tag));

    write_uint32(socket, ciphertext.size());
    boost::asio::write(socket, boost::asio::buffer(ciphertext));

    std::cout << "Encrypted message sent to client." << std::endl;
}

uint32_t TLSClient::read_uint32(tcp::socket& socket)
{
    uint32_t val;
    boost::asio::read(socket, boost::asio::buffer(&val, sizeof(val)));
    return ntohl(val);
}

void TLSClient::write_uint32(tcp::socket& socket, uint32_t val)
{
    uint32_t net_val = htonl(val);
    boost::asio::write(socket, boost::asio::buffer(&net_val, sizeof(net_val)));
}

EVP_PKEY* TLSClient::d2i_PUBKEY_from_vector(const std::vector<uint8_t>& data)
{
    const unsigned char* ptr = data.data();
    return d2i_PUBKEY(nullptr, &ptr, data.size());
}

std::vector<uint8_t> TLSClient::sha256(const std::vector<uint8_t>& input)
{
    std::vector<uint8_t> output(32);
    SHA256(input.data(), input.size(), output.data());
    return output;
}
