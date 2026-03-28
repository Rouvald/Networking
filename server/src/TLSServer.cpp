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

TLSServer::TLSServer(boost::asio::io_context& io_context, const btcp::endpoint& endpoint)
    : _acceptor(io_context, endpoint), _handshake_state(HandshakeState::IDLE)
{
    /*BIO* bp{BIO_new_fp(stdout, BIO_NOCLOSE)};
    EVP_PKEY_print_private(bp, _rsa.get_key(), 1, NULL);
    EVP_PKEY_print_public(bp, _rsa.get_key(), 1, NULL);
    BIO_free(bp);*/
}

void TLSServer::start_accept()
{
    btcp::socket socket(_acceptor.get_executor());
    _acceptor.accept(socket);
    std::cout << "Client connected." << '\n';

    _handshake_state = HandshakeState::WAIT_CLIENT_HELLO;
    handle_handshake(socket);
}

void TLSServer::handle_handshake(btcp::socket& socket)
{
    switch (_handshake_state)
    {
        case HandshakeState::WAIT_CLIENT_HELLO:
        {
            process_client_hello(socket);
            break;
        }
        case HandshakeState::SEND_SERVER_HELLO:
        {
            send_server_hello(socket);
            break;
        }
        case HandshakeState::WAIT_CLIENT_FINISHED:
        {
            process_client_finished(socket);
            break;
        }
        case HandshakeState::IDLE:
        case HandshakeState::HANDSHAKE_COMPLETE:
            // TODO: Implement logic for other states
            break;
    }
}

void TLSServer::process_client_hello(btcp::socket& socket)
{
    _timer.start();

    const uint32_t pub_len{UtilsNetwork::read_uint32(socket)};
    _client_public_key.resize(pub_len);
    boost::asio::read(socket, boost::asio::buffer(_client_public_key));

    _handshake_state = HandshakeState::SEND_SERVER_HELLO;
    handle_handshake(socket);  // Continue to the next state
}

void TLSServer::send_server_hello(btcp::socket& socket)
{
    std::vector<uint8_t> server_pub{_server_ecdh.get_public_key_der()};
    UtilsNetwork::write_uint32(socket, server_pub.size());
    boost::asio::write(socket, boost::asio::buffer(server_pub));

    _handshake_state = HandshakeState::WAIT_CLIENT_FINISHED;
}

void TLSServer::process_client_finished(btcp::socket& socket)
{
    EVP_PKEY* client_key{UtilsCrypto::d2i_PUBKEY_from_vector(_client_public_key)};
    const std::vector<uint8_t> shared_secret{_server_ecdh.compute_shared_secret(client_key)};
    EVP_PKEY_free(client_key);
    const std::vector<uint8_t> aes_key{UtilsCrypto::sha256(shared_secret)};

    AESCrypto aes(aes_key);

    _timer.stop();
    _timer.print("Server handshake");

    std::vector<uint8_t> ivKey(AES_IV_KEY_SIZE);
    boost::asio::read(socket, boost::asio::buffer(ivKey));

    std::vector<uint8_t> tag(AES_KEY_SIZE / 2);
    boost::asio::read(socket, boost::asio::buffer(tag));

    const uint32_t ct_len{UtilsNetwork::read_uint32(socket)};
    std::vector<uint8_t> ciphertext(ct_len);
    boost::asio::read(socket, boost::asio::buffer(ciphertext));

    std::vector<uint8_t> plaintext{aes.decrypt(ciphertext, ivKey, tag)};
    std::cout << "Decrypted message from server: " << std::string(plaintext.begin(), plaintext.end()) << '\n';

    _handshake_state = HandshakeState::HANDSHAKE_COMPLETE;
}
