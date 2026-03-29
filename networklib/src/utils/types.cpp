#include "utils/types.h"
#include <stdexcept>

constexpr uint8_t AMOUNT_8_BITS{8};
constexpr uint8_t AMOUNT_16_BITS{16};
constexpr uint8_t AMOUNT_MAX_BYTE{0xFF};

// @note: ByteWriter's methods
void types::ByteWriter::writeUint8(uint8_t value)
{
    _buffer.push_back(value);
}

void types::ByteWriter::writeUint16(uint16_t value)
{
    _buffer.push_back(static_cast<uint8_t>(value >> AMOUNT_8_BITS));
    _buffer.push_back(static_cast<uint8_t>(value & AMOUNT_MAX_BYTE));
}

void types::ByteWriter::writeUint24(uint32_t value)
{
    _buffer.push_back(static_cast<uint8_t>(value >> AMOUNT_16_BITS));
    _buffer.push_back(static_cast<uint8_t>((value >> AMOUNT_8_BITS) & AMOUNT_MAX_BYTE));
    _buffer.push_back(static_cast<uint8_t>(value & AMOUNT_MAX_BYTE));
}

void types::ByteWriter::writeBytes(const std::vector<uint8_t>& data)
{
    _buffer.insert(_buffer.end(), data.begin(), data.end());
}

// @note: ByteReader's methods
uint8_t types::ByteReader::readUint8()
{
    ensureAvailable(1);
    return _buffer[_pos++];
}

uint16_t types::ByteReader::readUint16()
{
    ensureAvailable(2);
    uint16_t value = (static_cast<uint16_t>(_buffer[_pos]) << AMOUNT_8_BITS) | static_cast<uint16_t>(_buffer[_pos + 1]);
    _pos += 2;
    return value;
}

uint32_t types::ByteReader::readUint24()
{
    ensureAvailable(3);
    uint32_t value = (static_cast<uint32_t>(_buffer[_pos]) << AMOUNT_16_BITS) |
                     (static_cast<uint32_t>(_buffer[_pos + 1]) << AMOUNT_8_BITS) | static_cast<uint32_t>(_buffer[_pos + 2]);
    _pos += 3;
    return value;
}

std::vector<uint8_t> types::ByteReader::readBytes(size_t length)
{
    ensureAvailable(length);
    std::vector<uint8_t> data(_buffer.begin() + _pos, _buffer.begin() + _pos + length);
    _pos += length;
    return data;
}

void types::ByteReader::skip(size_t length)
{
    ensureAvailable(length);
    _pos += length;
}

void types::ByteReader::ensureAvailable(const size_t& len) const
{
    if (_pos + len > _buffer.size())
    {
        throw std::out_of_range("Buffer underflow in ByteReader");
    }
}

// @note: TLSPlaintext's methods
std::vector<uint8_t> types::TLSPlaintext::serialize() const
{
    ByteWriter w;
    w.writeUint8(_type);
    w.writeUint16(_legacyVersion);
    // Length of fragment
    w.writeUint16(static_cast<uint16_t>(_fragment.size()));
    w.writeBytes(_fragment);
    return w.getBuffer();
}

types::TLSPlaintext types::TLSPlaintext::deserialize(const std::vector<uint8_t>& buf)
{
    ByteReader reader(buf);
    TLSPlaintext rec;
    rec._type = reader.readUint8();
    rec._legacyVersion = reader.readUint16();
    uint16_t len = reader.readUint16();
    rec._fragment = reader.readBytes(len);
    return rec;
}

// @note: TLSCiphertext's methods
std::vector<uint8_t> types::TLSCiphertext::serialize() const
{
    ByteWriter writer;
    writer.writeUint8(_type);
    writer.writeUint16(_legacyVersion);

    writer.writeUint16(static_cast<uint16_t>(_encryptedRecord.size()));
    writer.writeBytes(_encryptedRecord);
    return writer.getBuffer();
}

types::TLSCiphertext types::TLSCiphertext::deserialize(const std::vector<uint8_t>& buf)
{
    ByteReader reader(buf);
    TLSCiphertext rec;
    rec._type = reader.readUint8();
    rec._legacyVersion = reader.readUint16();
    const uint16_t len{reader.readUint16()};
    rec._encryptedRecord = reader.readBytes(len);
    return rec;
}
