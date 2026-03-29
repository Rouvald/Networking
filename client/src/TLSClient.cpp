#include "tlsclient.h"
#include "crypto/aescrypto.h"
#include "utils/functions.h"
#include <boost/asio.hpp>
#include <openssl/evp.h>
#include <openssl/x509.h>

TLSClient::TLSClient(boost::asio::io_context& ioContext, const std::string& host, uint16_t port) : _socket(ioContext)
{
    btcp::resolver resolver(ioContext);
    boost::asio::connect(_socket, resolver.resolve(host, std::to_string(port)));
}

void TLSClient::runHandshakeAndSend()
{
    _timer.start();

    std::vector<uint8_t> clientPub{_clientEcdh.getPublicKeyDer()};
    functions::network::writeUint32(_socket, static_cast<uint32_t>(clientPub.size()));
    boost::asio::write(_socket, boost::asio::buffer(clientPub));

    _timer.stop();
    std::cout << "Client START read from server: " << _timer.lastElapsedMs() << " ms\n";
    _timer.start();

    const uint32_t serverPubLength{functions::network::readUint32(_socket)};

    _timer.stop();
    std::cout << "Client END read from server: " << _timer.lastElapsedMs() << " ms\n";
    _timer.start();

    std::vector<uint8_t> serverPub(serverPubLength);
    boost::asio::read(_socket, boost::asio::buffer(serverPub));

    EVP_PKEY* serverKey{functions::crypto::d2iPubKeyFromVector(serverPub)};
    const std::vector<uint8_t> sharedSecret{_clientEcdh.computeSharedSecret(serverKey)};
    EVP_PKEY_free(serverKey);
    auto aesKey{functions::crypto::sha256(sharedSecret)};

    AESCrypto aes(aesKey);

    _timer.stop();
    std::cout << "Client handshake: " << _timer.lastElapsedMs() << " ms\n";

    const std::string message{"Hello from client! Add some useless info for testing"};
    std::vector<uint8_t> ivKey{AESCrypto::generateIv()};
    std::vector<uint8_t> tag;
    std::vector<uint8_t> ciphertext{aes.encrypt(std::vector<uint8_t>(message.begin(), message.end()), ivKey, tag)};

    boost::asio::write(_socket, boost::asio::buffer(ivKey));
    boost::asio::write(_socket, boost::asio::buffer(tag));

    functions::network::writeUint32(_socket, static_cast<uint32_t>(ciphertext.size()));
    boost::asio::write(_socket, boost::asio::buffer(ciphertext));

    std::cout << "Encrypted message sent to server." << '\n';
}
