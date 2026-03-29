#include "network/handshakemessages.h"
#include "utils/types.h"
#include <stdexcept>

namespace
{
std::vector<uint8_t> extractHandshakeBody(const std::vector<uint8_t>& buf, HandshakeType expectedType)
{
    if (buf.size() >= 4)
    {
        const auto parsed = HandshakeMessage::deserialize(buf);
        if (parsed.msgType == expectedType && parsed.body.size() + 4 == buf.size())
        {
            return parsed.body;
        }
    }
    return buf;
}
}

std::vector<uint8_t> HandshakeMessage::serialize() const
{
    types::ByteWriter writer;
    writer.writeUint8(static_cast<uint8_t>(msgType));
    writer.writeUint24(static_cast<uint32_t>(body.size()));
    writer.writeBytes(body);
    return writer.getBuffer();
}

HandshakeMessage HandshakeMessage::deserialize(const std::vector<uint8_t>& buf)
{
    types::ByteReader reader(buf);
    HandshakeMessage handshakeMessage;
    handshakeMessage.msgType = static_cast<HandshakeType>(reader.readUint8());
    uint32_t bodyLength = reader.readUint24();
    handshakeMessage.body = reader.readBytes(bodyLength);
    return handshakeMessage;
}

HandshakeMessage ClientHello::toMessage() const
{
    types::ByteWriter writer;
    writer.writeUint16(legacyVersion);
    writer.writeBytes(random);
    writer.writeUint8(static_cast<uint8_t>(sessionId.size()));
    writer.writeBytes(sessionId);
    writer.writeUint16(static_cast<uint16_t>(cipherSuites.size() * 2));
    for (auto cipherSuite : cipherSuites)
    {
        writer.writeUint16(cipherSuite);
    }
    writer.writeUint8(static_cast<uint8_t>(compressionMethods.size()));
    for (auto compressionMethod : compressionMethods)
    {
        writer.writeUint8(compressionMethod);
    }
    writer.writeUint16(static_cast<uint16_t>(extensions.size()));
    writer.writeBytes(extensions);
    return HandshakeMessage{HandshakeType::client_hello, writer.getBuffer()};
}

ClientHello ClientHello::parseBody(const std::vector<uint8_t>& body)
{
    types::ByteReader reader(body);
    ClientHello clientHello;
    clientHello.legacyVersion = reader.readUint16();
    clientHello.random = reader.readBytes(32);
    uint8_t sessionIdLength = reader.readUint8();
    clientHello.sessionId = reader.readBytes(sessionIdLength);
    uint16_t cipherSuitesLength = reader.readUint16();
    for (size_t i = 0; i < cipherSuitesLength / 2; ++i)
    {
        clientHello.cipherSuites.push_back(reader.readUint16());
    }
    uint8_t compressionMethodsLength = reader.readUint8();
    clientHello.compressionMethods = reader.readBytes(compressionMethodsLength);
    uint16_t extensionsLength = reader.readUint16();
    clientHello.extensions = reader.readBytes(extensionsLength);
    return clientHello;
}

HandshakeMessage ServerHello::toMessage() const
{
    types::ByteWriter writer;
    writer.writeUint16(legacyVersion);
    writer.writeBytes(random);
    writer.writeUint8(static_cast<uint8_t>(sessionId.size()));
    writer.writeBytes(sessionId);
    writer.writeUint16(cipherSuite);
    writer.writeUint8(compressionMethod);
    writer.writeUint16(static_cast<uint16_t>(extensions.size()));
    writer.writeBytes(extensions);
    return HandshakeMessage{HandshakeType::server_hello, writer.getBuffer()};
}

ServerHello ServerHello::parseBody(const std::vector<uint8_t>& body)
{
    types::ByteReader reader(body);
    ServerHello serverHello;
    serverHello.legacyVersion = reader.readUint16();
    serverHello.random = reader.readBytes(32);
    uint8_t sessionIdLength = reader.readUint8();
    serverHello.sessionId = reader.readBytes(sessionIdLength);
    serverHello.cipherSuite = reader.readUint16();
    serverHello.compressionMethod = reader.readUint8();
    uint16_t extensionsLength = reader.readUint16();
    serverHello.extensions = reader.readBytes(extensionsLength);
    return serverHello;
}

HandshakeMessage Finished::toMessage() const
{
    types::ByteWriter writer;
    writer.writeBytes(verifyData);
    return HandshakeMessage{HandshakeType::finished, writer.getBuffer()};
}

Finished Finished::parseBody(const std::vector<uint8_t>& body)
{
    Finished finished;
    finished.verifyData = body;
    return finished;
}

void ExtensionWriter::writeSupportedVersions(const std::vector<uint16_t>& versions)
{
    appendUint16(0x002b);
    types::ByteWriter writer;
    writer.writeUint16(static_cast<uint16_t>(versions.size() * 2));
    for (auto version : versions)
    {
        writer.writeUint16(version);
    }
    appendLengthPrefixed(writer.getBuffer());
}

void ExtensionWriter::writeKeyShare(const std::vector<KeyShareEntry>& entries)
{
    appendUint16(0x0033);
    types::ByteWriter writer;
    writer.writeUint16(0);
    size_t lengthPosition = writer.getBuffer().size() - 2;
    for (const auto& [group, key] : entries)
    {
        writer.writeUint16(group);
        writer.writeUint16(static_cast<uint16_t>(key.size()));
        writer.writeBytes(key);
    }

    auto buffer = writer.getBuffer();
    uint16_t listLength = static_cast<uint16_t>(buffer.size() - lengthPosition - 2);
    buffer[lengthPosition] = static_cast<uint8_t>(listLength >> 8);
    buffer[lengthPosition + 1] = static_cast<uint8_t>(listLength & 0xFF);
    appendLengthPrefixed(buffer);
}

void ExtensionWriter::appendUint16(uint16_t value)
{
    _extensions.push_back(static_cast<uint8_t>(value >> 8));
    _extensions.push_back(static_cast<uint8_t>(value & 0xFF));
}

void ExtensionWriter::appendLengthPrefixed(const std::vector<uint8_t>& data)
{
    _extensions.push_back(static_cast<uint8_t>(data.size() >> 8));
    _extensions.push_back(static_cast<uint8_t>(data.size() & 0xFF));
    _extensions.insert(_extensions.end(), data.begin(), data.end());
}

KeyShareEntry parseKeyShare(const std::vector<uint8_t>& extBuf)
{
    types::ByteReader reader(extBuf);
    while (reader.bytesRemaining() >= 4)
    {
        uint16_t type = reader.readUint16();
        uint16_t length = reader.readUint16();
        if (type == 0x0033)
        {
            types::ByteReader inner(reader.readBytes(length));
            uint16_t group = inner.readUint16();
            uint16_t keyLength = inner.readUint16();
            std::vector<uint8_t> key = inner.readBytes(keyLength);
            return {group, key};
        }
        reader.skip(length);
    }
    throw std::runtime_error("KeyShare extension not found");
}

EncryptedExtensions EncryptedExtensions::parseBody(const std::vector<uint8_t>& buf)
{
    types::ByteReader reader(extractHandshakeBody(buf, HandshakeType::encrypted_extensions));
    EncryptedExtensions encryptedExtensions;
    const uint16_t extensionsLength = reader.readUint16();
    encryptedExtensions.extensions = reader.readBytes(extensionsLength);
    return encryptedExtensions;
}

HandshakeMessage EncryptedExtensions::toMessage() const
{
    types::ByteWriter writer;
    writer.writeUint16(static_cast<uint16_t>(extensions.size()));
    writer.writeBytes(extensions);
    return HandshakeMessage{HandshakeType::encrypted_extensions, writer.getBuffer()};
}

Certificate Certificate::parseBody(const std::vector<uint8_t>& buf)
{
    types::ByteReader reader(extractHandshakeBody(buf, HandshakeType::certificate));
    Certificate certificate;

    const uint8_t contextLength = reader.readUint8();
    reader.skip(contextLength);

    types::ByteReader certificatesReader(reader.readBytes(reader.readUint24()));
    while (certificatesReader.hasRemaining())
    {
        certificate.certList.push_back(certificatesReader.readBytes(certificatesReader.readUint24()));
        certificatesReader.skip(certificatesReader.readUint16());
    }

    return certificate;
}

HandshakeMessage Certificate::toMessage() const
{
    types::ByteWriter certificatesWriter;
    for (const auto& cert : certList)
    {
        certificatesWriter.writeUint24(static_cast<uint32_t>(cert.size()));
        certificatesWriter.writeBytes(cert);
        certificatesWriter.writeUint16(0);
    }

    types::ByteWriter writer;
    writer.writeUint8(0);
    writer.writeUint24(static_cast<uint32_t>(certificatesWriter.getBuffer().size()));
    writer.writeBytes(certificatesWriter.getBuffer());
    return HandshakeMessage{HandshakeType::certificate, writer.getBuffer()};
}

CertificateVerify CertificateVerify::parseBody(const std::vector<uint8_t>& buf)
{
    types::ByteReader reader(extractHandshakeBody(buf, HandshakeType::certificate_verify));
    CertificateVerify certificateVerify;
    certificateVerify.scheme = static_cast<SignatureScheme>(reader.readUint16());
    certificateVerify.signature = reader.readBytes(reader.readUint16());
    return certificateVerify;
}

HandshakeMessage CertificateVerify::toMessage() const
{
    types::ByteWriter writer;
    writer.writeUint16(static_cast<uint16_t>(scheme));
    writer.writeUint16(static_cast<uint16_t>(signature.size()));
    writer.writeBytes(signature);
    return HandshakeMessage{HandshakeType::certificate_verify, writer.getBuffer()};
}
