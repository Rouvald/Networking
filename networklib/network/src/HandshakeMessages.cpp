#include <HandshakeMessages.h>
#include <iobytes.h>
#include <stdexcept>

std::vector<uint8_t> HandshakeMessage::serialize() const
{
    ByteWriter w;
    w.write_uint8(static_cast<uint8_t>(msg_type));
    w.write_uint24(static_cast<uint32_t>(body.size()));
    w.write_bytes(body);
    return w.get_buffer();
}

HandshakeMessage HandshakeMessage::deserialize(const std::vector<uint8_t>& buf)
{
    ByteReader reader(buf);
    HandshakeMessage hm;
    hm.msg_type = static_cast<HandshakeType>(reader.read_uint8());
    uint32_t len = reader.read_uint24();
    hm.body = reader.read_bytes(len);
    return hm;
}

HandshakeMessage ClientHello::to_message() const
{
    ByteWriter writer;
    writer.write_uint16(legacy_version);
    writer.write_bytes(random);
    writer.write_uint8(static_cast<uint8_t>(session_id.size()));
    writer.write_bytes(session_id);
    writer.write_uint16(static_cast<uint16_t>(cipher_suites.size() * 2));
    for (auto value : cipher_suites)
    {
        writer.write_uint16(value);
    }
    writer.write_uint8(static_cast<uint8_t>(compression_methods.size()));
    for (auto value : compression_methods)
    {
        writer.write_uint8(value);
    }
    writer.write_uint16(static_cast<uint16_t>(extensions.size()));
    writer.write_bytes(extensions);
    return HandshakeMessage{HandshakeType::client_hello, writer.get_buffer()};
}

ClientHello ClientHello::parse_body(const std::vector<uint8_t>& body)
{
    ByteReader reader(body);
    ClientHello client_hello;
    client_hello.legacy_version = reader.read_uint16();
    client_hello.random = reader.read_bytes(32);
    uint8_t sid_len = reader.read_uint8();
    client_hello.session_id = reader.read_bytes(sid_len);
    uint16_t cs_len = reader.read_uint16();
    for (size_t i = 0; i < cs_len / 2; ++i)
    {
        client_hello.cipher_suites.push_back(reader.read_uint16());
    }
    uint8_t cm_len = reader.read_uint8();
    client_hello.compression_methods = reader.read_bytes(cm_len);
    uint16_t ext_len = reader.read_uint16();
    client_hello.extensions = reader.read_bytes(ext_len);
    return client_hello;
}

HandshakeMessage ServerHello::to_message() const
{
    ByteWriter writer;
    writer.write_uint16(legacy_version);
    writer.write_bytes(random);
    writer.write_uint8(static_cast<uint8_t>(session_id.size()));
    writer.write_bytes(session_id);
    writer.write_uint16(cipher_suite);
    writer.write_uint8(compression_method);
    writer.write_uint16(static_cast<uint16_t>(extensions.size()));
    writer.write_bytes(extensions);
    return HandshakeMessage{HandshakeType::server_hello, writer.get_buffer()};
}

ServerHello ServerHello::parse_body(const std::vector<uint8_t>& body)
{
    ByteReader reader(body);
    ServerHello sh;
    sh.legacy_version = reader.read_uint16();
    sh.random = reader.read_bytes(32);
    uint8_t sid_len = reader.read_uint8();
    sh.session_id = reader.read_bytes(sid_len);
    sh.cipher_suite = reader.read_uint16();
    sh.compression_method = reader.read_uint8();
    uint16_t ext_len = reader.read_uint16();
    sh.extensions = reader.read_bytes(ext_len);
    return sh;
}

HandshakeMessage Finished::to_message() const
{
    ByteWriter writer;
    writer.write_bytes(verify_data);
    return HandshakeMessage{HandshakeType::finished, writer.get_buffer()};
}

Finished Finished::parse_body(const std::vector<uint8_t>& body)
{
    Finished finished;
    finished.verify_data = body;
    return finished;
}

void ExtensionWriter::write_supported_versions(const std::vector<uint16_t>& versions)
{
    // type 0x002b
    append_uint16(0x002b);
    ByteWriter writer;
    writer.write_uint16(versions.size() * 2);
    for (auto v : versions)
        writer.write_uint16(v);
    append_length_prefixed(writer.get_buffer());
}
void ExtensionWriter::write_key_share(const std::vector<KeyShareEntry>& entries)
{
    // type 0x0033
    append_uint16(0x0033);
    ByteWriter writer;
    // placeholder for list length
    writer.write_uint16(0);
    size_t len_pos = writer.get_buffer().size() - 2;
    for (const auto& [group, key] : entries)
    {
        writer.write_uint16(group);
        writer.write_uint16(key.size());
        writer.write_bytes(key);
    }
    // fix list length
    auto buf = writer.get_buffer();
    uint16_t list_len = buf.size() - len_pos - 2;
    buf[len_pos] = static_cast<uint8_t>(list_len >> 8);
    buf[len_pos + 1] = static_cast<uint8_t>(list_len & 0xFF);
    append_length_prefixed(buf);
}

void ExtensionWriter::append_uint16(uint16_t v)
{
    extensions_.push_back(static_cast<uint8_t>(v >> 8));
    extensions_.push_back(static_cast<uint8_t>(v & 0xFF));
}
void ExtensionWriter::append_length_prefixed(const std::vector<uint8_t>& data)
{
    extensions_.push_back(uint8_t(data.size() >> 8));
    extensions_.push_back(uint8_t(data.size() & 0xFF));
    extensions_.insert(extensions_.end(), data.begin(), data.end());
}

static KeyShareEntry parse_key_share(const std::vector<uint8_t>& ext_buf)
{
    ByteReader r(ext_buf);
    while (r.bytes_remaining() >= 4)
    {
        uint16_t type = r.read_uint16();
        uint16_t length = r.read_uint16();
        if (type == 0x0033)
        {
            ByteReader inner(r.read_bytes(length));
            // uint16_t list_len = inner.read_uint16();
            uint16_t group = inner.read_uint16();
            uint16_t key_len = inner.read_uint16();
            std::vector<uint8_t> key = inner.read_bytes(key_len);
            return {group, key};
        }
        else
        {
            r.skip(length);
        }
    }
    throw std::runtime_error("KeyShare extension not found");
}