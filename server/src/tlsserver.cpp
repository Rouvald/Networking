#include "crypto/aescrypto.h"
#include "tlsserver.h"
#include "utils/functions.h"
#include <boost/asio.hpp>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

TLSServer::TLSServer(boost::asio::io_context& ioContext, const btcp::endpoint& endpoint)
    : _acceptor(ioContext, endpoint), _handshakeState(HandshakeState::IDLE)
{
    /*BIO* bp{BIO_new_fp(stdout, BIO_NOCLOSE)};
    EVP_PKEY_print_private(bp, _rsa.getKey(), 1, NULL);
    EVP_PKEY_print_public(bp, _rsa.getKey(), 1, NULL);
    BIO_free(bp);*/
}

void TLSServer::startAccept()
{
    btcp::socket socket(_acceptor.get_executor());
    _acceptor.accept(socket);
    std::cout << "Client connected." << '\n';

    _handshakeState = HandshakeState::WAIT_CLIENT_HELLO;
    handleHandshake(socket);
}

void TLSServer::handleHandshake(btcp::socket& socket)
{
    switch (_handshakeState)
    {
        case HandshakeState::WAIT_CLIENT_HELLO:
        {
            processClientHello(socket);
            break;
        }
        case HandshakeState::SEND_SERVER_HELLO:
        {
            sendServerHello(socket);
            break;
        }
        case HandshakeState::WAIT_CLIENT_FINISHED:
        {
            processClientFinished(socket);
            break;
        }
        case HandshakeState::IDLE:
        case HandshakeState::HANDSHAKE_COMPLETE:
            break;
    }
}

void TLSServer::processClientHello(btcp::socket& socket)
{
    _timer.start();

    const uint32_t publicKeyLength{functions::network::readUint32(socket)};
    _clientPublicKey.resize(publicKeyLength);
    boost::asio::read(socket, boost::asio::buffer(_clientPublicKey));

    _handshakeState = HandshakeState::SEND_SERVER_HELLO;
    handleHandshake(socket);
}

void TLSServer::sendServerHello(btcp::socket& socket)
{
    std::vector<uint8_t> serverPublicKey{_serverEcdh.getPublicKeyDer()};
    functions::network::writeUint32(socket, static_cast<uint32_t>(serverPublicKey.size()));
    boost::asio::write(socket, boost::asio::buffer(serverPublicKey));

    _handshakeState = HandshakeState::WAIT_CLIENT_FINISHED;
}

void TLSServer::processClientFinished(btcp::socket& socket)
{
    EVP_PKEY* clientKey{functions::crypto::d2iPubKeyFromVector(_clientPublicKey)};
    const std::vector<uint8_t> sharedSecret{_serverEcdh.computeSharedSecret(clientKey)};
    EVP_PKEY_free(clientKey);
    const std::vector<uint8_t> aesKey{functions::crypto::sha256(sharedSecret)};

    AESCrypto aes(aesKey);

    _timer.stop();
    std::cout << "Server handshake: " << _timer.lastElapsedMs() << " ms\n";

    std::vector<uint8_t> ivKey(types::vars::AES_IV_KEY_SIZE);
    boost::asio::read(socket, boost::asio::buffer(ivKey));

    std::vector<uint8_t> tag(types::vars::AES_KEY_SIZE / 2);
    boost::asio::read(socket, boost::asio::buffer(tag));

    const uint32_t ciphertextLength{functions::network::readUint32(socket)};
    std::vector<uint8_t> ciphertext(ciphertextLength);
    boost::asio::read(socket, boost::asio::buffer(ciphertext));

    std::vector<uint8_t> plaintext{aes.decrypt(ciphertext, ivKey, tag)};
    std::cout << "Decrypted message from server: " << std::string(plaintext.begin(), plaintext.end()) << '\n';

    _handshakeState = HandshakeState::HANDSHAKE_COMPLETE;
}
