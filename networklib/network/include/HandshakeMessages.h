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

enum HandshakeType : uint8_t
{
    client_hello = 1,
    server_hello = 2,
    hello_retry_request = 6,
    encrypted_extensions = 8,
    certificate = 11,
    certificate_verify = 15,
    finished = 20
};

struct KeyShareEntry
{
    uint16_t group;
    std::vector<uint8_t> key;
};

// Base Handshake message
struct HandshakeMessage
{
    HandshakeType msg_type;
    std::vector<uint8_t> body;

    std::vector<uint8_t> serialize() const;
    static HandshakeMessage deserialize(const std::vector<uint8_t>& buf);
};

// ClientHello
struct ClientHello
{
    uint16_t legacy_version = 0x0303;  // Legacy record version, fixed to 0x0303 per RFC 8446
    std::vector<uint8_t> random;  // 32 bytes
    std::vector<uint8_t> session_id;
    std::vector<uint16_t> cipher_suites;
    std::vector<uint8_t> compression_methods;
    std::vector<uint8_t> extensions;

    HandshakeMessage to_message() const;
    static ClientHello parse_body(const std::vector<uint8_t>& body);
};

// ServerHello
struct ServerHello
{
    uint16_t legacy_version = 0x0303;
    std::vector<uint8_t> random;
    std::vector<uint8_t> session_id;
    uint16_t cipher_suite;
    uint8_t compression_method;
    std::vector<uint8_t> extensions;

    HandshakeMessage to_message() const;
    static ServerHello parse_body(const std::vector<uint8_t>& body);
};

// Finished
struct Finished
{
    std::vector<uint8_t> verify_data;

    HandshakeMessage to_message() const;
    static Finished parse_body(const std::vector<uint8_t>& body);
};

class ExtensionWriter
{
public:
    void write_supported_versions(const std::vector<uint16_t>& versions);
    void write_key_share(const std::vector<KeyShareEntry>& entries);
    std::vector<uint8_t> finalize() const { return extensions_; }

private:
    std::vector<uint8_t> extensions_;

    void append_uint16(uint16_t v);
    void append_length_prefixed(const std::vector<uint8_t>& data);
};

struct EncryptedExtensions
{
    std::vector<uint8_t> extensions;
    static EncryptedExtensions parse_body(const std::vector<uint8_t>& buf);
    HandshakeMessage to_message() const;
};
struct Certificate
{
    std::vector<std::vector<uint8_t>> cert_list;
    static Certificate parse_body(const std::vector<uint8_t>&);
    HandshakeMessage to_message() const;
};
struct CertificateVerify
{
    SignatureScheme scheme;
    std::vector<uint8_t> signature;
    static CertificateVerify parse_body(const std::vector<uint8_t>&);
    HandshakeMessage to_message() const;
};

static KeyShareEntry parse_key_share(const std::vector<uint8_t>& ext_buf);

#endif  // HANDSHAKEMESSAGES_H
