#include "network/handshakemanager.h"
#include "network/handshakemessages.h"
#include "network/keyschedule.h"
#include "utils/functions.h"
#include "utils/types.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdexcept>

namespace
{
constexpr uint16_t TLS_LEGACY_VERSION{0x0303};

TrafficKeyMaterial deriveDirectionalKeys(
    const std::vector<uint8_t>& baseSecret, const std::string& label, const std::vector<uint8_t>& transcriptHash)
{
    return deriveTrafficKeyMaterial(deriveTrafficSecret(baseSecret, label, transcriptHash));
}
}

void HandshakeManager::doClientHandshake()
{
    ClientHello clientHello;
    clientHello.legacyVersion = TLS_LEGACY_VERSION;
    clientHello.random.resize(32);
    if (RAND_bytes(clientHello.random.data(), static_cast<int>(clientHello.random.size())) != 1)
    {
        throw std::runtime_error("RAND_bytes failed");
    }
    clientHello.sessionId.clear();
    clientHello.cipherSuites = {0x1301};
    clientHello.compressionMethods = {0x00};

    ExtensionWriter extensionWriter;
    extensionWriter.writeSupportedVersions({0x0304});
    std::vector<uint8_t> clientPublicKey = _ecdhe.getPublicKeyDer();
    extensionWriter.writeKeyShare({{0x001d, clientPublicKey}});
    clientHello.extensions = extensionWriter.finalize();

    std::vector<uint8_t> clientHelloBytes = clientHello.toMessage().serialize();
    appendTranscript(clientHelloBytes);
    sendHandshakeMessage(clientHelloBytes);

    std::vector<uint8_t> serverHelloBytes = receiveHandshakeMessage(HandshakeType::server_hello);
    appendTranscript(serverHelloBytes);
    ServerHello serverHello = ServerHello::parseBody(HandshakeMessage::deserialize(serverHelloBytes).body);

    KeyShareEntry shareEntry = parseKeyShare(serverHello.extensions);
    const uint8_t* peerKeyData = shareEntry.key.data();
    EVP_PKEY* peer = d2i_PUBKEY(nullptr, &peerKeyData, static_cast<long>(shareEntry.key.size()));
    if (peer == nullptr)
    {
        throw std::runtime_error("Invalid server public key DER");
    }
    std::vector<uint8_t> sharedSecret = _ecdhe.computeSharedSecret(peer);
    EVP_PKEY_free(peer);

    _earlySecret = deriveEarlySecret(_psk);
    _handshakeSecret = deriveHandshakeSecret(_earlySecret, sharedSecret);
    installHandshakeTrafficKeys(true);

    std::vector<uint8_t> encryptedExtensionsBytes = receiveHandshakeMessage(HandshakeType::encrypted_extensions);
    appendTranscript(encryptedExtensionsBytes);
    (void)EncryptedExtensions::parseBody(encryptedExtensionsBytes);

    std::vector<uint8_t> serverFinishedBytes = receiveHandshakeMessage(HandshakeType::finished);
    Finished serverFinished = Finished::parseBody(serverFinishedBytes);
    std::vector<uint8_t> expected =
        HKDF::expandLabel(_handshakeSecret, "finished", transcriptHash(), types::vars::SHA256_KEY_SIZE);
    if (serverFinished.verifyData != expected)
    {
        throw std::runtime_error("Server Finished verification failed");
    }
    appendTranscript(serverFinishedBytes);

    std::vector<uint8_t> verifyData =
        HKDF::expandLabel(_handshakeSecret, "finished", transcriptHash(), types::vars::SHA256_KEY_SIZE);
    Finished clientFinished{verifyData};
    std::vector<uint8_t> clientFinishedBytes = clientFinished.toMessage().serialize();
    appendTranscript(clientFinishedBytes);
    sendHandshakeMessage(clientFinishedBytes);

    _masterSecret = deriveMasterSecret(_handshakeSecret);
    installApplicationTrafficKeys(true);
}

void HandshakeManager::doServerHandshake()
{
    std::vector<uint8_t> clientHelloBytes = receiveHandshakeMessage(HandshakeType::client_hello);
    appendTranscript(clientHelloBytes);
    ClientHello clientHello = ClientHello::parseBody(HandshakeMessage::deserialize(clientHelloBytes).body);

    KeyShareEntry clientShare = parseKeyShare(clientHello.extensions);
    const uint8_t* peerKeyData = clientShare.key.data();
    EVP_PKEY* clientPeerKey = d2i_PUBKEY(nullptr, &peerKeyData, static_cast<long>(clientShare.key.size()));
    if (clientPeerKey == nullptr)
    {
        throw std::runtime_error("Invalid client public key DER");
    }

    ServerHello serverHello;
    serverHello.legacyVersion = TLS_LEGACY_VERSION;
    serverHello.random.resize(32);
    if (RAND_bytes(serverHello.random.data(), static_cast<int>(serverHello.random.size())) != 1)
    {
        EVP_PKEY_free(clientPeerKey);
        throw std::runtime_error("RAND_bytes failed");
    }
    serverHello.sessionId = clientHello.sessionId;
    serverHello.cipherSuite = 0x1301;
    serverHello.compressionMethod = 0x00;

    ExtensionWriter extensionWriter;
    extensionWriter.writeSupportedVersions({0x0304});
    std::vector<uint8_t> serverPublicKey = _ecdhe.getPublicKeyDer();
    extensionWriter.writeKeyShare({{0x001d, serverPublicKey}});
    serverHello.extensions = extensionWriter.finalize();

    std::vector<uint8_t> serverHelloBytes = serverHello.toMessage().serialize();
    appendTranscript(serverHelloBytes);
    sendHandshakeMessage(serverHelloBytes);

    std::vector<uint8_t> sharedSecret = _ecdhe.computeSharedSecret(clientPeerKey);
    EVP_PKEY_free(clientPeerKey);
    _earlySecret = deriveEarlySecret(_psk);
    _handshakeSecret = deriveHandshakeSecret(_earlySecret, sharedSecret);
    installHandshakeTrafficKeys(false);

    EncryptedExtensions encryptedExtensions;
    std::vector<uint8_t> encryptedExtensionsBytes = encryptedExtensions.toMessage().serialize();
    appendTranscript(encryptedExtensionsBytes);
    sendHandshakeMessage(encryptedExtensionsBytes);

    std::vector<uint8_t> verifyData =
        HKDF::expandLabel(_handshakeSecret, "finished", transcriptHash(), types::vars::SHA256_KEY_SIZE);
    Finished serverFinished{verifyData};
    std::vector<uint8_t> serverFinishedBytes = serverFinished.toMessage().serialize();
    appendTranscript(serverFinishedBytes);
    sendHandshakeMessage(serverFinishedBytes);

    std::vector<uint8_t> clientFinishedBytes = receiveHandshakeMessage(HandshakeType::finished);
    Finished clientFinished = Finished::parseBody(clientFinishedBytes);
    std::vector<uint8_t> expected =
        HKDF::expandLabel(_handshakeSecret, "finished", transcriptHash(), types::vars::SHA256_KEY_SIZE);
    if (clientFinished.verifyData != expected)
    {
        throw std::runtime_error("Client Finished verification failed");
    }
    appendTranscript(clientFinishedBytes);

    _masterSecret = deriveMasterSecret(_handshakeSecret);
    installApplicationTrafficKeys(false);
}

void HandshakeManager::appendTranscript(const std::vector<uint8_t>& messageBytes)
{
    _transcript.insert(_transcript.end(), messageBytes.begin(), messageBytes.end());
}

void HandshakeManager::sendHandshakeMessage(const std::vector<uint8_t>& messageBytes)
{
    auto encodedRecord = _record.encode(static_cast<uint8_t>(ContentType::handshake), TLS_LEGACY_VERSION, messageBytes);
    functions::network::writeVector(_socket, encodedRecord.serialize());
}

std::vector<uint8_t> HandshakeManager::receiveHandshakeMessage(HandshakeType expectedType)
{
    std::vector<uint8_t> rawRecord = functions::network::readVector(_socket);
    auto tlsRecord = types::TLSCiphertext::deserialize(rawRecord);
    std::vector<uint8_t> messageBytes = _record.decode(tlsRecord);
    HandshakeMessage message = HandshakeMessage::deserialize(messageBytes);
    if (message.msgType != expectedType)
    {
        throw std::runtime_error("Unexpected handshake message type");
    }
    return messageBytes;
}

void HandshakeManager::installHandshakeTrafficKeys(bool isClientRole)
{
    const std::vector<uint8_t> hash = transcriptHash();
    const TrafficKeyMaterial clientKeys = deriveDirectionalKeys(_handshakeSecret, "c hs traffic", hash);
    const TrafficKeyMaterial serverKeys = deriveDirectionalKeys(_handshakeSecret, "s hs traffic", hash);

    if (isClientRole)
    {
        _record.setWriteKeys(clientKeys.key, clientKeys.iv);
        _record.setReadKeys(serverKeys.key, serverKeys.iv);
        return;
    }

    _record.setWriteKeys(serverKeys.key, serverKeys.iv);
    _record.setReadKeys(clientKeys.key, clientKeys.iv);
}

void HandshakeManager::installApplicationTrafficKeys(bool isClientRole)
{
    const std::vector<uint8_t> hash = transcriptHash();
    const TrafficKeyMaterial clientKeys = deriveDirectionalKeys(_masterSecret, "c ap traffic", hash);
    const TrafficKeyMaterial serverKeys = deriveDirectionalKeys(_masterSecret, "s ap traffic", hash);

    if (isClientRole)
    {
        _record.setWriteKeys(clientKeys.key, clientKeys.iv);
        _record.setReadKeys(serverKeys.key, serverKeys.iv);
        return;
    }

    _record.setWriteKeys(serverKeys.key, serverKeys.iv);
    _record.setReadKeys(clientKeys.key, clientKeys.iv);
}

std::vector<uint8_t> HandshakeManager::transcriptHash() const
{
    return functions::crypto::sha256(_transcript);
}
