#include "network/tlsrecordlayer.h"

TLSRecordLayer::TLSRecordLayer(const std::vector<uint8_t>& key, const std::vector<uint8_t>& ivKey)
    : _aead(key), _ivKey(ivKey), _seqNum(0)
{
    if (ivKey.size() != _ivKey.size())
    {
        throw std::invalid_argument("IV size mismatch");
    }
}

types::TLSCiphertext TLSRecordLayer::encode(uint8_t type, uint16_t legacyVersion, const std::vector<uint8_t>& plaintext)
{
    types::ByteWriter header;
    header.writeUint8(type);
    header.writeUint16(legacyVersion);
    header.writeUint16(0);
    std::vector<uint8_t> additionalData = header.getBuffer();

    std::vector<uint8_t> nonce = computeNonce();
    std::vector<uint8_t> encrypted = _aead.encrypt(plaintext, additionalData, nonce);

    types::TLSCiphertext record;
    record._type = type;
    record._legacyVersion = legacyVersion;
    record._encryptedRecord = encrypted;

    _seqNum++;
    return record;
}

std::vector<uint8_t> TLSRecordLayer::decode(const types::TLSCiphertext& record)
{
    types::ByteWriter header;
    header.writeUint8(record._type);
    header.writeUint16(record._legacyVersion);
    header.writeUint16(static_cast<uint16_t>(record._encryptedRecord.size()));
    std::vector<uint8_t> additionalData = header.getBuffer();

    std::vector<uint8_t> nonce = computeNonce();
    std::vector<uint8_t> plaintext = _aead.decrypt(record._encryptedRecord, additionalData, nonce);

    _seqNum++;
    return plaintext;
}

std::vector<uint8_t> TLSRecordLayer::computeNonce() const
{
    if (_ivKey.size() != types::vars::AES_IV_KEY_SIZE)
    {
        throw std::invalid_argument("Unsupported IV size, expected 12 bytes");
    }

    std::vector<uint8_t> nonce(types::vars::AES_IV_KEY_SIZE);
    uint8_t seqBytes[8];
    for (int i = 0; i < 8; ++i)
    {
        seqBytes[7 - i] = static_cast<uint8_t>((_seqNum >> (8 * i)) & 0xFF);
    }

    for (size_t i = 0; i < 12; ++i)
    {
        if (i < 4)
        {
            nonce[i] = _ivKey[i];
        }
        else
        {
            nonce[i] = _ivKey[i] ^ seqBytes[i - 4];
        }
    }
    return nonce;
}
