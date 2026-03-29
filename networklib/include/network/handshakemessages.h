#ifndef HANDSHAKEMESSAGES_H
#define HANDSHAKEMESSAGES_H

#include <cstdint>
#include <vector>

enum class ContentType : uint8_t
{
    change_cipher_spec = 20,
    alert = 21,
    handshake = 22,
    application_data = 23
};

enum class HandshakeType : uint8_t
{
    client_hello = 1,
    server_hello = 2,
    hello_retry_request = 6,
    encrypted_extensions = 8,
    certificate = 11,
    certificate_verify = 15,
    finished = 20
};

enum class SignatureScheme : uint16_t
{
    rsa_pkcs1_sha256 = 0x0401,
    ecdsa_secp256r1_sha256 = 0x0403,
    rsa_pss_rsae_sha256 = 0x0804
};

struct KeyShareEntry
{
    uint16_t group;
    std::vector<uint8_t> key;
};

// Base Handshake message
struct HandshakeMessage
{
    HandshakeType msgType;
    std::vector<uint8_t> body;

    std::vector<uint8_t> serialize() const;
    static HandshakeMessage deserialize(const std::vector<uint8_t>& buf);
};

// ClientHello
struct ClientHello
{
    uint16_t legacyVersion = 0x0303;  // Legacy record version, fixed to 0x0303 per RFC 8446
    std::vector<uint8_t> random;  // 32 bytes
    std::vector<uint8_t> sessionId;
    std::vector<uint16_t> cipherSuites;
    std::vector<uint8_t> compressionMethods;
    std::vector<uint8_t> extensions;

    HandshakeMessage toMessage() const;
    static ClientHello parseBody(const std::vector<uint8_t>& body);
};

// ServerHello
struct ServerHello
{
    uint16_t legacyVersion = 0x0303;
    std::vector<uint8_t> random;
    std::vector<uint8_t> sessionId;
    uint16_t cipherSuite;
    uint8_t compressionMethod;
    std::vector<uint8_t> extensions;

    HandshakeMessage toMessage() const;
    static ServerHello parseBody(const std::vector<uint8_t>& body);
};

// Finished
struct Finished
{
    std::vector<uint8_t> verifyData;

    HandshakeMessage toMessage() const;
    static Finished parseBody(const std::vector<uint8_t>& body);
};

class ExtensionWriter
{
public:
    void writeSupportedVersions(const std::vector<uint16_t>& versions);
    void writeKeyShare(const std::vector<KeyShareEntry>& entries);
    std::vector<uint8_t> finalize() const { return _extensions; }

private:
    std::vector<uint8_t> _extensions;

    void appendUint16(uint16_t value);
    void appendLengthPrefixed(const std::vector<uint8_t>& data);
};

struct EncryptedExtensions
{
    std::vector<uint8_t> extensions;
    static EncryptedExtensions parseBody(const std::vector<uint8_t>& buf);
    HandshakeMessage toMessage() const;
};
struct Certificate
{
    std::vector<std::vector<uint8_t>> certList;
    static Certificate parseBody(const std::vector<uint8_t>&);
    HandshakeMessage toMessage() const;
};
struct CertificateVerify
{
    SignatureScheme scheme;
    std::vector<uint8_t> signature;
    static CertificateVerify parseBody(const std::vector<uint8_t>&);
    HandshakeMessage toMessage() const;
};

KeyShareEntry parseKeyShare(const std::vector<uint8_t>& extBuf);

#endif  // HANDSHAKEMESSAGES_H
