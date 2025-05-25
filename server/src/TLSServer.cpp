#include <AESCrypto.h>
#include <cstdint>
#include <boost/asio/io_context.hpp>
#include <boost/asio/buffer.hpp>
#include <TLSServer.h>
#include <iostream>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <vector>

constexpr uint8_t SHA256_KEY_SIZE{32};

TLSServer::TLSServer(boost::asio::io_context& io_context, const btcp::endpoint& endpoint) : _acceptor(io_context, endpoint)
{
    start_accept();
}

void TLSServer::start_accept()
{
    btcp::socket socket(_acceptor.get_executor());
    _acceptor.accept(socket);
    std::cout << "Client connected." << '\n';

    handle_handshake(socket);
}

void TLSServer::handle_handshake(btcp::socket& socket)
{
    const uint32_t pub_len = read_uint32(socket);
    std::vector<uint8_t> client_pub(pub_len);
    boost::asio::read(socket, boost::asio::buffer(client_pub));

    std::vector<uint8_t> server_pub = _server_ecdh.get_public_key_der();
    write_uint32(socket, server_pub.size());
    boost::asio::write(socket, boost::asio::buffer(server_pub));

    EVP_PKEY* client_key = d2i_PUBKEY_from_vector(client_pub);
    const std::vector<uint8_t> shared_secret = _server_ecdh.compute_shared_secret(client_key);
    EVP_PKEY_free(client_key);
    auto aes_key = sha256(shared_secret);

    AES_Crypto aes(aes_key);

    std::vector<uint8_t> ivKey(AES_IV_KEY_SIZE);
    boost::asio::read(socket, boost::asio::buffer(ivKey));

    std::vector<uint8_t> tag(AES_KEY_SIZE / 2);
    boost::asio::read(socket, boost::asio::buffer(tag));

    uint32_t const ct_len = read_uint32(socket);
    std::vector<uint8_t> ciphertext(ct_len);
    boost::asio::read(socket, boost::asio::buffer(ciphertext));

    std::vector<uint8_t> plaintext = aes.decrypt(ciphertext, ivKey, tag);
    std::cout << "Decrypted message from server: " << std::string(plaintext.begin(), plaintext.end()) << '\n';
}

uint32_t TLSServer::read_uint32(btcp::socket& socket)
{
    uint32_t val{0};
    boost::asio::read(socket, boost::asio::buffer(&val, sizeof(val)));
    return ntohl(val);
}

void TLSServer::write_uint32(btcp::socket& socket, uint32_t val)
{
    uint32_t net_val = htonl(val);
    boost::asio::write(socket, boost::asio::buffer(&net_val, sizeof(net_val)));
}

EVP_PKEY* TLSServer::d2i_PUBKEY_from_vector(const std::vector<uint8_t>& data)
{
    const unsigned char* ptr = data.data();
    return d2i_PUBKEY(nullptr, &ptr, data.size());
}

std::vector<uint8_t> TLSServer::sha256(const std::vector<uint8_t>& input)
{
    std::vector<uint8_t> output(SHA256_KEY_SIZE);
    SHA256(input.data(), input.size(), output.data());
    return output;
}
