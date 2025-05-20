#include <TLSServer.h>
#include <iostream>
#include <AESCrypto.h>

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

TLSServer::TLSServer(boost::asio::io_context& io_context, tcp::endpoint endpoint) : acceptor(io_context, endpoint)
{
    start_accept();
}

void TLSServer::start_accept()
{
    tcp::socket socket(acceptor.get_executor());
    acceptor.accept(socket);
    std::cout << "Client connected." << std::endl;

    handle_handshake(socket);
}

void TLSServer::handle_handshake(tcp::socket& socket)
{
    uint32_t pub_len = read_uint32(socket);
    std::vector<uint8_t> client_pub(pub_len);
    boost::asio::read(socket, boost::asio::buffer(client_pub));

    std::vector<uint8_t> server_pub = server_ecdh.get_public_key_der();
    write_uint32(socket, server_pub.size());
    boost::asio::write(socket, boost::asio::buffer(server_pub));

    EVP_PKEY* client_key = d2i_PUBKEY_from_vector(client_pub);
    std::vector<uint8_t> shared_secret = server_ecdh.compute_shared_secret(client_key);
    EVP_PKEY_free(client_key);
    auto aes_key = sha256(shared_secret);

    AES_Crypto aes(aes_key);

    std::vector<uint8_t> iv(12);
    boost::asio::read(socket, boost::asio::buffer(iv));

    std::vector<uint8_t> tag(16);
    boost::asio::read(socket, boost::asio::buffer(tag));

    uint32_t ct_len = read_uint32(socket);
    std::vector<uint8_t> ciphertext(ct_len);
    boost::asio::read(socket, boost::asio::buffer(ciphertext));

    std::vector<uint8_t> plaintext = aes.decrypt(ciphertext, iv, tag);
    std::cout << "Decrypted message from server: " << std::string(plaintext.begin(), plaintext.end()) << std::endl;
}

uint32_t TLSServer::read_uint32(tcp::socket& socket)
{
    uint32_t val;
    boost::asio::read(socket, boost::asio::buffer(&val, sizeof(val)));
    return ntohl(val);
}

void TLSServer::write_uint32(tcp::socket& socket, uint32_t val)
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
    std::vector<uint8_t> output(32);
    SHA256(input.data(), input.size(), output.data());
    return output;
}