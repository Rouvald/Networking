#include "network/handshakemanager.h"
#include "utils/types.h"
#include "utils/functions.h"
#include "network/handshakemessages.h"
#include "crypto/ecdhecrypto.h"
#include "network/keyschedule.h"
#include <openssl/rand.h>

void HandshakeManager::doClientHandshake()
{
    ClientHello clientHello;
    clientHello.legacyVersion = 0x0303;
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
    extensionWriter.writeKeyShare({
        {0x001d, clientPublicKey}
    });
    clientHello.extensions = extensionWriter.finalize();

    std::vector<uint8_t> clientHelloBytes = clientHello.toMessage().serialize();
    _transcript.insert(_transcript.end(), clientHelloBytes.begin(), clientHelloBytes.end());

    {
        auto encodedRecord = _record.encode(static_cast<uint8_t>(ContentType::handshake), 0x0303, clientHelloBytes);
        functions::network::writeVector(_socket, encodedRecord.serialize());
    }

    std::vector<uint8_t> rawRecord = functions::network::readVector(_socket);
    auto tlsRecord = types::TLSCiphertext::deserialize(rawRecord);
    std::vector<uint8_t> serverHelloBytes = _record.decode(tlsRecord);
    HandshakeMessage serverHelloMessage = HandshakeMessage::deserialize(serverHelloBytes);
    if (serverHelloMessage.msgType != HandshakeType::server_hello)
    {
        throw std::runtime_error("Expected ServerHello");
    }
    _transcript.insert(_transcript.end(), serverHelloBytes.begin(), serverHelloBytes.end());
    ServerHello serverHello = ServerHello::parseBody(serverHelloMessage.body);

    KeyShareEntry shareEntry = parseKeyShare(serverHello.extensions);
    const uint8_t* peerKeyData = shareEntry.key.data();
    EVP_PKEY* peer = d2i_PUBKEY(nullptr, &peerKeyData, static_cast<long>(shareEntry.key.size()));
    if (peer == nullptr)
    {
        throw std::runtime_error("Invalid server public key DER");
    }
    std::vector<uint8_t> sharedSecret = _ecdhe.computeSharedSecret(peer);
    EVP_PKEY_free(peer);

    {
        std::vector<uint8_t> encryptedRecord = functions::network::readVector(_socket);
        auto encryptedTlsRecord = types::TLSCiphertext::deserialize(encryptedRecord);
        std::vector<uint8_t> body = _record.decode(encryptedTlsRecord);
        _transcript.insert(_transcript.end(), body.begin(), body.end());
        EncryptedExtensions encryptedExtensions = EncryptedExtensions::parseBody(body);
    }

    Certificate certificate;
    {
        std::vector<uint8_t> encryptedRecord = functions::network::readVector(_socket);
        auto encryptedTlsRecord = types::TLSCiphertext::deserialize(encryptedRecord);
        std::vector<uint8_t> body = _record.decode(encryptedTlsRecord);
        _transcript.insert(_transcript.end(), body.begin(), body.end());
        certificate = Certificate::parseBody(body);
    }

    CertificateVerify certificateVerify;
    {
        std::vector<uint8_t> encryptedRecord = functions::network::readVector(_socket);
        auto encryptedTlsRecord = types::TLSCiphertext::deserialize(encryptedRecord);
        std::vector<uint8_t> body = _record.decode(encryptedTlsRecord);
        _transcript.insert(_transcript.end(), body.begin(), body.end());
        certificateVerify = CertificateVerify::parseBody(body);
    }

    {
        std::vector<uint8_t> encryptedRecord = functions::network::readVector(_socket);
        auto encryptedTlsRecord = types::TLSCiphertext::deserialize(encryptedRecord);
        std::vector<uint8_t> body = _record.decode(encryptedTlsRecord);
        _transcript.insert(_transcript.end(), body.begin(), body.end());
        Finished serverFinished = Finished::parseBody(body);
        std::vector<uint8_t> expected =
            HKDF::expandLabel(_handshakeSecret, "finished", transcriptHash(), types::vars::SHA256_KEY_SIZE);
        if (serverFinished.verifyData != expected)
        {
            throw std::runtime_error("Server Finished verification failed");
        }
    }

    {
        std::vector<uint8_t> verifyData =
            HKDF::expandLabel(_handshakeSecret, "finished", transcriptHash(), types::vars::SHA256_KEY_SIZE);
        Finished clientFinished{verifyData};
        std::vector<uint8_t> clientFinishedBody = clientFinished.toMessage().serialize();
        _transcript.insert(_transcript.end(), clientFinishedBody.begin(), clientFinishedBody.end());

        auto encodedRecord = _record.encode(static_cast<uint8_t>(ContentType::handshake), 0x0303, clientFinishedBody);
        functions::network::writeVector(_socket, encodedRecord.serialize());
    }

    _masterSecret = deriveMasterSecret(_handshakeSecret);
    std::vector<uint8_t> appKey = HKDF::expandLabel(_masterSecret, "key", transcriptHash(), types::vars::SHA256_KEY_SIZE);
    std::vector<uint8_t> appIv = HKDF::expandLabel(_masterSecret, "iv", transcriptHash(), types::vars::AES_IV_KEY_SIZE);
    _record = TLSRecordLayer(appKey, appIv);
    _record.resetSequence();
}

std::vector<uint8_t> HandshakeManager::transcriptHash() const
{
    return functions::crypto::sha256(_transcript);
}
