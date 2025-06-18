#ifndef IOBYTES_H
#define IOBYTES_H

#include <cstdint>
#include <vector>

class ByteWriter
{
public:
    ByteWriter() = default;

    void write_uint8(uint8_t value);
    void write_uint16(uint16_t value);
    void write_uint24(uint32_t value);
    void write_bytes(const std::vector<uint8_t>& data);

    const std::vector<uint8_t>& get_buffer() const { return _buffer; }

private:
    std::vector<uint8_t> _buffer;
};

class ByteReader
{
public:
    explicit ByteReader(const std::vector<uint8_t>& buffer) : _buffer(buffer) {}

    uint8_t read_uint8();
    uint16_t read_uint16();
    uint32_t read_uint24();
    std::vector<uint8_t> read_bytes(size_t length);
    void skip(size_t length);

    size_t bytes_remaining() const { return _buffer.size() - _pos; }
    bool has_remaining() const { return _pos < _buffer.size(); }

private:
    const std::vector<uint8_t>& _buffer;
    size_t _pos{0};

    void ensure_available(const size_t& len) const;
};

struct TLSPlaintext
{
    uint8_t _type{};
    uint16_t _legacy_version{};
    std::vector<uint8_t> _fragment;

    std::vector<uint8_t> serialize() const;
    static TLSPlaintext deserialize(const std::vector<uint8_t>& buf);
};

struct TLSCiphertext
{
    uint8_t _type{};
    uint16_t _legacy_version{};
    std::vector<uint8_t> _encrypted_record;

    std::vector<uint8_t> serialize() const;
    static TLSCiphertext deserialize(const std::vector<uint8_t>& buf);
};

#endif  // IOBYTES_H
