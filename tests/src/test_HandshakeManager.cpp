#include "network/handshakemanager.h"
#include "network/handshakemessages.h"
#include "network/keyschedule.h"
#include "network/tlsrecordlayer.h"
#include "crypto/ecdhecrypto.h"
#include "utils/functions.h"
#include "utils/types.h"
#include <gtest/gtest.h>
#include <boost/asio.hpp>
#include <exception>
#include <string>
#include <thread>
#include <vector>

namespace
{
constexpr uint16_t kLegacyVersion{0x0303};

std::vector<uint8_t> makeBytes(size_t size, uint8_t value)
{
    return std::vector<uint8_t>(size, value);
}

TLSRecordLayer makeInitialRecordLayer()
{
    return TLSRecordLayer(makeBytes(types::vars::AES_KEY_SIZE, 0x00), makeBytes(types::vars::AES_IV_KEY_SIZE, 0x00));
}

void createConnectedSockets(btcp::socket& server, btcp::socket& client)
{
    auto& ioContext = static_cast<boost::asio::io_context&>(server.get_executor().context());
    btcp::acceptor acceptor(ioContext, btcp::endpoint(btcp::v4(), 0));
    const unsigned short port = acceptor.local_endpoint().port();
    client.connect(btcp::endpoint(boost::asio::ip::make_address("127.0.0.1"), port));
    acceptor.accept(server);
}

void rethrowIfSet(const std::exception_ptr& error)
{
    if (error != nullptr)
    {
        std::rethrow_exception(error);
    }
}

std::string exceptionMessage(const std::exception_ptr& error)
{
    try
    {
        rethrowIfSet(error);
    }
    catch (const std::exception& ex)
    {
        return ex.what();
    }
    return {};
}

void appendTranscript(std::vector<uint8_t>& transcript, const std::vector<uint8_t>& messageBytes)
{
    transcript.insert(transcript.end(), messageBytes.begin(), messageBytes.end());
}

std::vector<uint8_t> readDecodedRecord(TLSRecordLayer& record, btcp::socket& socket)
{
    const auto rawRecord = functions::network::readVector(socket);
    const auto tlsRecord = types::TLSCiphertext::deserialize(rawRecord);
    return record.decode(tlsRecord);
}

void writeHandshakeRecord(TLSRecordLayer& record, btcp::socket& socket, const std::vector<uint8_t>& messageBytes)
{
    const auto encoded = record.encode(static_cast<uint8_t>(ContentType::handshake), kLegacyVersion, messageBytes);
    functions::network::writeVector(socket, encoded.serialize());
}

ClientHello makeClientHello(const std::vector<uint8_t>& publicKey)
{
    ClientHello clientHello;
    clientHello.legacyVersion = kLegacyVersion;
    clientHello.random = makeBytes(32, 0x11);
    clientHello.sessionId = {0xAB, 0xCD};
    clientHello.cipherSuites = {0x1301};
    clientHello.compressionMethods = {0x00};

    ExtensionWriter extensionWriter;
    extensionWriter.writeSupportedVersions({0x0304});
    extensionWriter.writeKeyShare({{0x001d, publicKey}});
    clientHello.extensions = extensionWriter.finalize();
    return clientHello;
}

ServerHello makeServerHello(const ClientHello& clientHello, const std::vector<uint8_t>& publicKey)
{
    ServerHello serverHello;
    serverHello.legacyVersion = kLegacyVersion;
    serverHello.random = makeBytes(32, 0x22);
    serverHello.sessionId = clientHello.sessionId;
    serverHello.cipherSuite = 0x1301;
    serverHello.compressionMethod = 0x00;

    ExtensionWriter extensionWriter;
    extensionWriter.writeSupportedVersions({0x0304});
    extensionWriter.writeKeyShare({{0x001d, publicKey}});
    serverHello.extensions = extensionWriter.finalize();
    return serverHello;
}

void installHandshakeKeys(
    TLSRecordLayer& record, const std::vector<uint8_t>& handshakeSecret, const std::vector<uint8_t>& transcript, bool isClientRole)
{
    const auto transcriptHash = functions::crypto::sha256(transcript);
    const auto clientKeys = deriveTrafficKeyMaterial(deriveTrafficSecret(handshakeSecret, "c hs traffic", transcriptHash));
    const auto serverKeys = deriveTrafficKeyMaterial(deriveTrafficSecret(handshakeSecret, "s hs traffic", transcriptHash));

    if (isClientRole)
    {
        record.setWriteKeys(clientKeys.key, clientKeys.iv);
        record.setReadKeys(serverKeys.key, serverKeys.iv);
        return;
    }

    record.setWriteKeys(serverKeys.key, serverKeys.iv);
    record.setReadKeys(clientKeys.key, clientKeys.iv);
}
}

TEST(HandshakeManagerTest, ClientAndServerCompleteHandshakeAndExchangeApplicationData)
{
    boost::asio::io_context ioContext;
    btcp::socket serverSocket(ioContext);
    btcp::socket clientSocket(ioContext);
    createConnectedSockets(serverSocket, clientSocket);

    TLSRecordLayer serverRecord(makeBytes(types::vars::AES_KEY_SIZE, 0x00), makeBytes(types::vars::AES_IV_KEY_SIZE, 0x00));
    TLSRecordLayer clientRecord(makeBytes(types::vars::AES_KEY_SIZE, 0x00), makeBytes(types::vars::AES_IV_KEY_SIZE, 0x00));
    HandshakeManager serverManager(serverSocket, serverRecord);
    HandshakeManager clientManager(clientSocket, clientRecord);

    std::exception_ptr serverError;
    std::exception_ptr clientError;

    std::thread serverThread([&]()
    {
        try
        {
            serverManager.doServerHandshake();
        }
        catch (...)
        {
            serverError = std::current_exception();
        }
    });

    std::thread clientThread([&]()
    {
        try
        {
            clientManager.doClientHandshake();
        }
        catch (...)
        {
            clientError = std::current_exception();
        }
    });

    clientThread.join();
    serverThread.join();

    EXPECT_NO_THROW(rethrowIfSet(clientError));
    EXPECT_NO_THROW(rethrowIfSet(serverError));

    const std::vector<uint8_t> clientPayload{'h', 'e', 'l', 'l', 'o'};
    const auto clientRecordBytes =
        clientRecord.encode(static_cast<uint8_t>(ContentType::application_data), kLegacyVersion, clientPayload).serialize();
    functions::network::writeVector(clientSocket, clientRecordBytes);

    const auto serverRaw = functions::network::readVector(serverSocket);
    const auto serverTlsRecord = types::TLSCiphertext::deserialize(serverRaw);
    EXPECT_EQ(serverRecord.decode(serverTlsRecord), clientPayload);

    const std::vector<uint8_t> serverPayload{'w', 'o', 'r', 'l', 'd'};
    const auto serverRecordBytes =
        serverRecord.encode(static_cast<uint8_t>(ContentType::application_data), kLegacyVersion, serverPayload).serialize();
    functions::network::writeVector(serverSocket, serverRecordBytes);

    const auto clientRaw = functions::network::readVector(clientSocket);
    const auto clientTlsRecord = types::TLSCiphertext::deserialize(clientRaw);
    EXPECT_EQ(clientRecord.decode(clientTlsRecord), serverPayload);
}

TEST(HandshakeManagerTest, ServerHandshakeRejectsUnexpectedFirstMessage)
{
    boost::asio::io_context ioContext;
    btcp::socket serverSocket(ioContext);
    btcp::socket clientSocket(ioContext);
    createConnectedSockets(serverSocket, clientSocket);

    TLSRecordLayer serverRecord(makeBytes(types::vars::AES_KEY_SIZE, 0x00), makeBytes(types::vars::AES_IV_KEY_SIZE, 0x00));
    HandshakeManager serverManager(serverSocket, serverRecord);
    std::exception_ptr serverError;

    std::thread serverThread([&]()
    {
        try
        {
            serverManager.doServerHandshake();
        }
        catch (...)
        {
            serverError = std::current_exception();
        }
    });

    TLSRecordLayer clientRecord = makeInitialRecordLayer();
    EncryptedExtensions encryptedExtensions;
    writeHandshakeRecord(clientRecord, clientSocket, encryptedExtensions.toMessage().serialize());

    serverThread.join();

    EXPECT_EQ(exceptionMessage(serverError), "Unexpected handshake message type");
}

TEST(HandshakeManagerTest, ServerHandshakeRejectsInvalidClientPublicKeyDer)
{
    boost::asio::io_context ioContext;
    btcp::socket serverSocket(ioContext);
    btcp::socket clientSocket(ioContext);
    createConnectedSockets(serverSocket, clientSocket);

    TLSRecordLayer serverRecord(makeBytes(types::vars::AES_KEY_SIZE, 0x00), makeBytes(types::vars::AES_IV_KEY_SIZE, 0x00));
    HandshakeManager serverManager(serverSocket, serverRecord);
    std::exception_ptr serverError;

    std::thread serverThread([&]()
    {
        try
        {
            serverManager.doServerHandshake();
        }
        catch (...)
        {
            serverError = std::current_exception();
        }
    });

    TLSRecordLayer clientRecord = makeInitialRecordLayer();
    const ClientHello clientHello = makeClientHello({0xDE, 0xAD, 0xBE, 0xEF});
    writeHandshakeRecord(clientRecord, clientSocket, clientHello.toMessage().serialize());

    serverThread.join();

    EXPECT_EQ(exceptionMessage(serverError), "Invalid client public key DER");
}

TEST(HandshakeManagerTest, ClientHandshakeRejectsInvalidServerPublicKeyDer)
{
    boost::asio::io_context ioContext;
    btcp::socket serverSocket(ioContext);
    btcp::socket clientSocket(ioContext);
    createConnectedSockets(serverSocket, clientSocket);

    TLSRecordLayer clientRecord(makeBytes(types::vars::AES_KEY_SIZE, 0x00), makeBytes(types::vars::AES_IV_KEY_SIZE, 0x00));
    HandshakeManager clientManager(clientSocket, clientRecord);
    std::exception_ptr clientError;

    std::thread clientThread([&]()
    {
        try
        {
            clientManager.doClientHandshake();
        }
        catch (...)
        {
            clientError = std::current_exception();
        }
    });

    TLSRecordLayer serverRecord = makeInitialRecordLayer();
    const auto clientHelloBytes = readDecodedRecord(serverRecord, serverSocket);
    const auto clientHello = ClientHello::parseBody(HandshakeMessage::deserialize(clientHelloBytes).body);
    const auto serverHello = makeServerHello(clientHello, {0xBA, 0xAD, 0xF0, 0x0D});
    writeHandshakeRecord(serverRecord, serverSocket, serverHello.toMessage().serialize());

    clientThread.join();

    EXPECT_EQ(exceptionMessage(clientError), "Invalid server public key DER");
}

TEST(HandshakeManagerTest, ClientHandshakeRejectsInvalidServerFinished)
{
    boost::asio::io_context ioContext;
    btcp::socket serverSocket(ioContext);
    btcp::socket clientSocket(ioContext);
    createConnectedSockets(serverSocket, clientSocket);

    TLSRecordLayer clientRecord(makeBytes(types::vars::AES_KEY_SIZE, 0x00), makeBytes(types::vars::AES_IV_KEY_SIZE, 0x00));
    HandshakeManager clientManager(clientSocket, clientRecord);
    std::exception_ptr clientError;

    std::thread clientThread([&]()
    {
        try
        {
            clientManager.doClientHandshake();
        }
        catch (...)
        {
            clientError = std::current_exception();
        }
    });

    TLSRecordLayer serverRecord = makeInitialRecordLayer();
    const auto clientHelloBytes = readDecodedRecord(serverRecord, serverSocket);
    std::vector<uint8_t> transcript = clientHelloBytes;
    const auto clientHello = ClientHello::parseBody(HandshakeMessage::deserialize(clientHelloBytes).body);

    const KeyShareEntry clientShare = parseKeyShare(clientHello.extensions);
    EVP_PKEY* clientPeerKey = functions::crypto::d2iPubKeyFromVector(clientShare.key);
    ASSERT_NE(clientPeerKey, nullptr);

    ECDHECrypto serverEcdhe;
    const auto serverHello = makeServerHello(clientHello, serverEcdhe.getPublicKeyDer());
    const auto serverHelloBytes = serverHello.toMessage().serialize();
    appendTranscript(transcript, serverHelloBytes);
    writeHandshakeRecord(serverRecord, serverSocket, serverHelloBytes);

    const auto sharedSecret = serverEcdhe.computeSharedSecret(clientPeerKey);
    EVP_PKEY_free(clientPeerKey);

    const auto handshakeSecret = deriveHandshakeSecret(deriveEarlySecret({}), sharedSecret);
    installHandshakeKeys(serverRecord, handshakeSecret, transcript, false);

    EncryptedExtensions encryptedExtensions;
    const auto encryptedExtensionsBytes = encryptedExtensions.toMessage().serialize();
    appendTranscript(transcript, encryptedExtensionsBytes);
    writeHandshakeRecord(serverRecord, serverSocket, encryptedExtensionsBytes);

    Finished badFinished{makeBytes(types::vars::SHA256_KEY_SIZE, 0xA5)};
    writeHandshakeRecord(serverRecord, serverSocket, badFinished.toMessage().serialize());

    clientThread.join();

    EXPECT_EQ(exceptionMessage(clientError), "Server Finished verification failed");
}

TEST(HandshakeManagerTest, ServerHandshakeRejectsInvalidClientFinished)
{
    boost::asio::io_context ioContext;
    btcp::socket serverSocket(ioContext);
    btcp::socket clientSocket(ioContext);
    createConnectedSockets(serverSocket, clientSocket);

    TLSRecordLayer serverRecord(makeBytes(types::vars::AES_KEY_SIZE, 0x00), makeBytes(types::vars::AES_IV_KEY_SIZE, 0x00));
    HandshakeManager serverManager(serverSocket, serverRecord);
    std::exception_ptr serverError;

    std::thread serverThread([&]()
    {
        try
        {
            serverManager.doServerHandshake();
        }
        catch (...)
        {
            serverError = std::current_exception();
        }
    });

    TLSRecordLayer clientRecord = makeInitialRecordLayer();
    ECDHECrypto clientEcdhe;
    const ClientHello clientHello = makeClientHello(clientEcdhe.getPublicKeyDer());
    const auto clientHelloBytes = clientHello.toMessage().serialize();
    std::vector<uint8_t> transcript = clientHelloBytes;
    writeHandshakeRecord(clientRecord, clientSocket, clientHelloBytes);

    const auto serverHelloBytes = readDecodedRecord(clientRecord, clientSocket);
    appendTranscript(transcript, serverHelloBytes);
    const auto serverHello = ServerHello::parseBody(HandshakeMessage::deserialize(serverHelloBytes).body);

    const KeyShareEntry serverShare = parseKeyShare(serverHello.extensions);
    EVP_PKEY* serverPeerKey = functions::crypto::d2iPubKeyFromVector(serverShare.key);
    ASSERT_NE(serverPeerKey, nullptr);

    const auto sharedSecret = clientEcdhe.computeSharedSecret(serverPeerKey);
    EVP_PKEY_free(serverPeerKey);

    const auto handshakeSecret = deriveHandshakeSecret(deriveEarlySecret({}), sharedSecret);
    installHandshakeKeys(clientRecord, handshakeSecret, transcript, true);

    const auto encryptedExtensionsBytes = readDecodedRecord(clientRecord, clientSocket);
    appendTranscript(transcript, encryptedExtensionsBytes);

    const auto serverFinishedBytes = readDecodedRecord(clientRecord, clientSocket);
    appendTranscript(transcript, serverFinishedBytes);

    Finished badFinished{makeBytes(types::vars::SHA256_KEY_SIZE, 0x5C)};
    writeHandshakeRecord(clientRecord, clientSocket, badFinished.toMessage().serialize());

    serverThread.join();

    EXPECT_EQ(exceptionMessage(serverError), "Client Finished verification failed");
}
