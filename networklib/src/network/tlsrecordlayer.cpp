#include "network/tlsrecordlayer.h"
#include "utils/types.h"
#include <stdexcept>

TLSRecordLayer::TLSRecordLayer(const std::vector<uint8_t>& key, const std::vector<uint8_t>& ivKey)
    : _aead(key), _ivKey(ivKey), _seqNum(0)
{
}

types::TLSCiphertext TLSRecordLayer::encode(uint8_t type, uint16_t legacyVersion, const std::vector<uint8_t>& plaintext)
{
    std::vector<uint8_t> nonce = computeNonce();
    std::vector<uint8_t> tag;
    std::vector<uint8_t> ciphertext = _aead.encrypt(plaintext, nonce, tag);

    // Layout: [tag (16 bytes)] [ciphertext]
    std::vector<uint8_t> encryptedRecord;
    encryptedRecord.insert(encryptedRecord.end(), tag.begin(), tag.end());
    encryptedRecord.insert(encryptedRecord.end(), ciphertext.begin(), ciphertext.end());

    types::TLSCiphertext record;
    record._type = type;
    record._legacyVersion = legacyVersion;
    record._encryptedRecord = std::move(encryptedRecord);

    _seqNum++;
    return record;
}

std::vector<uint8_t> TLSRecordLayer::decode(const types::TLSCiphertext& record)
{
    if (record._encryptedRecord.size() < types::vars::GCM_TAG_SIZE)
    {
        throw std::runtime_error("TLSRecord too short to contain GCM tag");
    }
    // Layout: [tag (16 bytes)] [ciphertext]
    std::vector<uint8_t> tag(record._encryptedRecord.begin(),
                             record._encryptedRecord.begin() + types::vars::GCM_TAG_SIZE);
    std::vector<uint8_t> ciphertext(record._encryptedRecord.begin() + types::vars::GCM_TAG_SIZE,
                                    record._encryptedRecord.end());

    std::vector<uint8_t> nonce = computeNonce();
    std::vector<uint8_t> plaintext = _aead.decrypt(ciphertext, nonce, tag);

    if (plaintext.empty() && !ciphertext.empty())
    {
        throw std::runtime_error("TLSRecord decryption failed: tag mismatch");
    }
    ++_seqNum;
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
