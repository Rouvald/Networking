#include <TLSRecordLayer.h>
#include <stdexcept>

TLSRecordLayer::TLSRecordLayer(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv_key)
    : _aead(key), _iv_key(iv_key), _seq_num(0)
{
    if (iv_key.size() != _iv_key.size())
    {
        throw std::invalid_argument("IV size mismatch");
    }
}

TLSCiphertext TLSRecordLayer::encode(uint8_t type, uint16_t legacy_version, const std::vector<uint8_t>& plaintext)
{
    ByteWriter header;
    header.write_uint8(type);
    header.write_uint16(legacy_version);
    header.write_uint16(0);
    std::vector<uint8_t> additional_data = header.get_buffer();

    std::vector<uint8_t> nonce = compute_nonce();

    std::vector<uint8_t> encrypted = _aead.encrypt(plaintext, additional_data, nonce);

    const auto len = static_cast<uint16_t>(encrypted.size());
    header = ByteWriter();
    header.write_uint8(type);
    header.write_uint16(legacy_version);
    header.write_uint16(len);

    TLSCiphertext rec;
    std::vector<uint8_t> hdr = header.get_buffer();
    rec._type = type;
    rec._legacy_version = legacy_version;
    rec._encrypted_record = encrypted;

    _seq_num++;

    return rec;
}

std::vector<uint8_t> TLSRecordLayer::decode(const TLSCiphertext& record)
{
    ByteWriter header;
    header.write_uint8(record._type);
    header.write_uint16(record._legacy_version);
    header.write_uint16(static_cast<uint16_t>(record._encrypted_record.size()));
    std::vector<uint8_t> additional_data = header.get_buffer();

    std::vector<uint8_t> nonce = compute_nonce();

    std::vector<uint8_t> plaintext = _aead.decrypt(record._encrypted_record, additional_data, nonce);

    _seq_num++;
    return plaintext;
}

std::vector<uint8_t> TLSRecordLayer::compute_nonce() const
{
    if (_iv_key.size() != AES_IV_KEY_SIZE)
    {
        throw std::invalid_argument("Unsupported IV size, expected 12 bytes");
    }
    std::vector<uint8_t> nonce(AES_IV_KEY_SIZE);
    uint8_t seq_bytes[8];
    for (int i = 0; i < 8; ++i)
    {
        seq_bytes[7 - i] = static_cast<uint8_t>((_seq_num >> (8 * i)) & 0xFF);
    }
    for (size_t i = 0; i < 12; ++i)
    {
        if (i < 4)
        {
            nonce[i] = _iv_key[i];
        }
        else
        {
            nonce[i] = _iv_key[i] ^ seq_bytes[i - 4];
        }
    }
    return nonce;
}