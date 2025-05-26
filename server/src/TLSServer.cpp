#include <AESCrypto.h>
#include <TLSServer.h>
#include <boost/asio.hpp>
#include <UtilsCrypto.h>
#include <cstdint>
#include <iostream>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <vector>

TLSServer::TLSServer(boost::asio::io_context& io_context, const btcp::endpoint& endpoint) : _acceptor(io_context, endpoint)
{
    BIO* bp{BIO_new_fp(stdout, BIO_NOCLOSE)};
    EVP_PKEY_print_private(bp, _rsa.get_key(), 1, NULL);
    EVP_PKEY_print_public(bp, _rsa.get_key(), 1, NULL);
    BIO_free(bp);
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
    const uint32_t pub_len{UtilsNetwork::read_uint32(socket)};
    std::vector<uint8_t> client_pub(pub_len);
    boost::asio::read(socket, boost::asio::buffer(client_pub));

    std::vector<uint8_t> server_pub{_server_ecdh.get_public_key_der()};
    UtilsNetwork::write_uint32(socket, server_pub.size());
    boost::asio::write(socket, boost::asio::buffer(server_pub));

    EVP_PKEY* client_key{UtilsCrypto::d2i_PUBKEY_from_vector(client_pub)};
    const std::vector<uint8_t> shared_secret{_server_ecdh.compute_shared_secret(client_key)};
    EVP_PKEY_free(client_key);
    const std::vector<uint8_t> aes_key{UtilsCrypto::sha256(shared_secret)};

    AESCrypto aes(aes_key);

    std::vector<uint8_t> ivKey(AES_IV_KEY_SIZE);
    boost::asio::read(socket, boost::asio::buffer(ivKey));

    std::vector<uint8_t> tag(AES_KEY_SIZE / 2);
    boost::asio::read(socket, boost::asio::buffer(tag));

    const uint32_t ct_len{UtilsNetwork::read_uint32(socket)};
    std::vector<uint8_t> ciphertext(ct_len);
    boost::asio::read(socket, boost::asio::buffer(ciphertext));

    std::vector<uint8_t> plaintext{aes.decrypt(ciphertext, ivKey, tag)};
    std::cout << "Decrypted message from server: " << std::string(plaintext.begin(), plaintext.end()) << '\n';
}
