#include "network/handshakemessages.h"
#include <gtest/gtest.h>
#include <stdexcept>
#include <vector>

namespace
{
std::vector<uint8_t> makeBytes(std::initializer_list<uint8_t> bytes)
{
    return std::vector<uint8_t>(bytes);
}
}

TEST(HandshakeMessagesTest, HandshakeMessageSerializeDeserializeRoundTrip)
{
    const HandshakeMessage message{HandshakeType::finished, makeBytes({0x01, 0x02, 0x03})};
    const HandshakeMessage restored = HandshakeMessage::deserialize(message.serialize());

    EXPECT_EQ(restored.msgType, message.msgType);
    EXPECT_EQ(restored.body, message.body);
}

TEST(HandshakeMessagesTest, ClientHelloRoundTrip)
{
    ExtensionWriter extensionWriter;
    extensionWriter.writeSupportedVersions({0x0304});
    extensionWriter.writeKeyShare({{0x001d, makeBytes({0xA1, 0xB2, 0xC3})}});

    ClientHello clientHello;
    clientHello.legacyVersion = 0x0303;
    clientHello.random = std::vector<uint8_t>(32, 0x11);
    clientHello.sessionId = makeBytes({0xAA, 0xBB});
    clientHello.cipherSuites = {0x1301, 0x1302};
    clientHello.compressionMethods = makeBytes({0x00});
    clientHello.extensions = extensionWriter.finalize();

    const HandshakeMessage restoredMessage = HandshakeMessage::deserialize(clientHello.toMessage().serialize());
    const ClientHello restored = ClientHello::parseBody(restoredMessage.body);

    EXPECT_EQ(restored.legacyVersion, clientHello.legacyVersion);
    EXPECT_EQ(restored.random, clientHello.random);
    EXPECT_EQ(restored.sessionId, clientHello.sessionId);
    EXPECT_EQ(restored.cipherSuites, clientHello.cipherSuites);
    EXPECT_EQ(restored.compressionMethods, clientHello.compressionMethods);
    EXPECT_EQ(restored.extensions, clientHello.extensions);
}

TEST(HandshakeMessagesTest, ServerHelloRoundTrip)
{
    ExtensionWriter extensionWriter;
    extensionWriter.writeKeyShare({{0x001d, makeBytes({0x01, 0x02, 0x03, 0x04})}});

    ServerHello serverHello;
    serverHello.legacyVersion = 0x0303;
    serverHello.random = std::vector<uint8_t>(32, 0x22);
    serverHello.sessionId = makeBytes({0x10, 0x20, 0x30});
    serverHello.cipherSuite = 0x1301;
    serverHello.compressionMethod = 0x00;
    serverHello.extensions = extensionWriter.finalize();

    const HandshakeMessage restoredMessage = HandshakeMessage::deserialize(serverHello.toMessage().serialize());
    const ServerHello restored = ServerHello::parseBody(restoredMessage.body);

    EXPECT_EQ(restored.legacyVersion, serverHello.legacyVersion);
    EXPECT_EQ(restored.random, serverHello.random);
    EXPECT_EQ(restored.sessionId, serverHello.sessionId);
    EXPECT_EQ(restored.cipherSuite, serverHello.cipherSuite);
    EXPECT_EQ(restored.compressionMethod, serverHello.compressionMethod);
    EXPECT_EQ(restored.extensions, serverHello.extensions);
}

TEST(HandshakeMessagesTest, FinishedParsesSerializedMessageAndRawBody)
{
    const std::vector<uint8_t> verifyData = makeBytes({0xAA, 0xBB, 0xCC});
    const std::vector<uint8_t> serialized = Finished{verifyData}.toMessage().serialize();

    EXPECT_EQ(Finished::parseBody(serialized).verifyData, verifyData);
    EXPECT_EQ(Finished::parseBody(verifyData).verifyData, verifyData);
}

TEST(HandshakeMessagesTest, EncryptedExtensionsParsesSerializedMessageAndRawBody)
{
    EncryptedExtensions encryptedExtensions;
    encryptedExtensions.extensions = makeBytes({0x01, 0x00, 0x02});

    const HandshakeMessage message = encryptedExtensions.toMessage();
    EXPECT_EQ(EncryptedExtensions::parseBody(message.serialize()).extensions, encryptedExtensions.extensions);

    EncryptedExtensions emptyEncryptedExtensions;
    emptyEncryptedExtensions.extensions.clear();
    EXPECT_EQ(EncryptedExtensions::parseBody(emptyEncryptedExtensions.toMessage().body).extensions,
              emptyEncryptedExtensions.extensions);
}

TEST(HandshakeMessagesTest, CertificateRoundTripWithMultipleEntries)
{
    Certificate certificate;
    certificate.certList = {
        makeBytes({0x01, 0x02, 0x03}),
        makeBytes({0x10, 0x20})
    };

    const std::vector<uint8_t> serialized = certificate.toMessage().serialize();
    const Certificate restored = Certificate::parseBody(serialized);

    EXPECT_EQ(restored.certList, certificate.certList);
}

TEST(HandshakeMessagesTest, CertificateVerifyRoundTrip)
{
    CertificateVerify certificateVerify;
    certificateVerify.scheme = SignatureScheme::rsa_pss_rsae_sha256;
    certificateVerify.signature = makeBytes({0xFE, 0xED, 0xFA, 0xCE});

    const std::vector<uint8_t> serialized = certificateVerify.toMessage().serialize();
    const CertificateVerify restored = CertificateVerify::parseBody(serialized);

    EXPECT_EQ(restored.scheme, certificateVerify.scheme);
    EXPECT_EQ(restored.signature, certificateVerify.signature);
}

TEST(HandshakeMessagesTest, ParseKeyShareSkipsOtherExtensionsAndFindsKeyShare)
{
    ExtensionWriter extensionWriter;
    extensionWriter.writeSupportedVersions({0x0304});
    extensionWriter.writeKeyShare({{0x001d, makeBytes({0x11, 0x22, 0x33})}});

    const KeyShareEntry entry = parseKeyShare(extensionWriter.finalize());
    EXPECT_EQ(entry.group, 0x001d);
    EXPECT_EQ(entry.key, makeBytes({0x11, 0x22, 0x33}));
}

TEST(HandshakeMessagesTest, ParseKeyShareThrowsWhenExtensionIsMissing)
{
    ExtensionWriter extensionWriter;
    extensionWriter.writeSupportedVersions({0x0304});

    EXPECT_THROW(parseKeyShare(extensionWriter.finalize()), std::runtime_error);
}
