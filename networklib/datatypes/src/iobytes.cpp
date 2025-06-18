#include <iobytes.h>
#include <stdexcept>

constexpr uint8_t AMOUNT_8_BITS{8};
constexpr uint8_t AMOUNT_16_BITS{16};
constexpr uint8_t AMOUNT_MAX_BYTE{0xFF};

// @note: ByteWriter's methods
void ByteWriter::write_uint8(uint8_t value)
{
    _buffer.push_back(value);
}

void ByteWriter::write_uint16(uint16_t value)
{
    _buffer.push_back(static_cast<uint8_t>(value >> AMOUNT_8_BITS));
    _buffer.push_back(static_cast<uint8_t>(value & AMOUNT_MAX_BYTE));
}

void ByteWriter::write_uint24(uint32_t value)
{
    _buffer.push_back(static_cast<uint8_t>(value >> AMOUNT_16_BITS));
    _buffer.push_back(static_cast<uint8_t>((value >> AMOUNT_8_BITS) & AMOUNT_MAX_BYTE));
    _buffer.push_back(static_cast<uint8_t>(value & AMOUNT_MAX_BYTE));
}

void ByteWriter::write_bytes(const std::vector<uint8_t>& data)
{
    _buffer.insert(_buffer.end(), data.begin(), data.end());
}

// @note: ByteReader's methods
uint8_t ByteReader::read_uint8()
{
    ensure_available(1);
    return _buffer[_pos++];
}

uint16_t ByteReader::read_uint16()
{
    ensure_available(2);
    uint16_t value = (static_cast<uint16_t>(_buffer[_pos]) << AMOUNT_8_BITS) | static_cast<uint16_t>(_buffer[_pos + 1]);
    _pos += 2;
    return value;
}

uint32_t ByteReader::read_uint24()
{
    ensure_available(3);
    uint32_t value = (static_cast<uint32_t>(_buffer[_pos]) << AMOUNT_16_BITS) |
                     (static_cast<uint32_t>(_buffer[_pos + 1]) << AMOUNT_8_BITS) | static_cast<uint32_t>(_buffer[_pos + 2]);
    _pos += 3;
    return value;
}

std::vector<uint8_t> ByteReader::read_bytes(size_t length)
{
    ensure_available(length);
    std::vector<uint8_t> data(_buffer.begin() + _pos, _buffer.begin() + _pos + length);
    _pos += length;
    return data;
}

void ByteReader::skip(size_t length)
{
    ensure_available(length);
    _pos += length;
}

void ByteReader::ensure_available(const size_t& len) const
{
    if (_pos + len > _buffer.size())
    {
        throw std::out_of_range("Buffer underflow in ByteReader");
    }
}

// @note: TLSPlaintext's methods
std::vector<uint8_t> TLSPlaintext::serialize() const
{
    ByteWriter w;
    w.write_uint8(_type);
    w.write_uint16(_legacy_version);
    // Length of fragment
    w.write_uint16(static_cast<uint16_t>(_fragment.size()));
    w.write_bytes(_fragment);
    return w.get_buffer();
}

TLSPlaintext TLSPlaintext::deserialize(const std::vector<uint8_t>& buf)
{
    ByteReader reader(buf);
    TLSPlaintext rec;
    rec._type = reader.read_uint8();
    rec._legacy_version = reader.read_uint16();
    uint16_t len = reader.read_uint16();
    rec._fragment = reader.read_bytes(len);
    return rec;
}

// @note: TLSCiphertext's methods
std::vector<uint8_t> TLSCiphertext::serialize() const
{
    ByteWriter writer;
    writer.write_uint8(_type);
    writer.write_uint16(_legacy_version);

    writer.write_uint16(static_cast<uint16_t>(_encrypted_record.size()));
    writer.write_bytes(_encrypted_record);
    return writer.get_buffer();
}

TLSCiphertext TLSCiphertext::deserialize(const std::vector<uint8_t>& buf)
{
    ByteReader reader(buf);
    TLSCiphertext rec;
    rec._type = reader.read_uint8();
    rec._legacy_version = reader.read_uint16();
    const uint16_t len{reader.read_uint16()};
    rec._encrypted_record = reader.read_bytes(len);
    return rec;
}