#include "network/tlsrecordlayer.h"
#include "utils/types.h"
#include <stdexcept>

TLSRecordLayer::TLSRecordLayer(const std::vector<uint8_t>& key, const std::vector<uint8_t>& ivKey)
{
    setReadKeys(key, ivKey);
    setWriteKeys(key, ivKey);
}

types::TLSCiphertext TLSRecordLayer::encode(uint8_t type, uint16_t legacyVersion, const std::vector<uint8_t>& plaintext)
{
    AESCrypto aead(_writeState.key);
    std::vector<uint8_t> nonce = computeNonce(_writeState);
    std::vector<uint8_t> tag;
    std::vector<uint8_t> ciphertext = aead.encrypt(plaintext, nonce, tag);

    // Layout: [tag (16 bytes)] [ciphertext]
    std::vector<uint8_t> encryptedRecord;
    encryptedRecord.insert(encryptedRecord.end(), tag.begin(), tag.end());
    encryptedRecord.insert(encryptedRecord.end(), ciphertext.begin(), ciphertext.end());

    types::TLSCiphertext record;
    record._type = type;
    record._legacyVersion = legacyVersion;
    record._encryptedRecord = std::move(encryptedRecord);

    ++_writeState.seqNum;
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

    AESCrypto aead(_readState.key);
    std::vector<uint8_t> nonce = computeNonce(_readState);
    std::vector<uint8_t> plaintext = aead.decrypt(ciphertext, nonce, tag);

    if (plaintext.empty() && !ciphertext.empty())
    {
        throw std::runtime_error("TLSRecord decryption failed: tag mismatch");
    }
    ++_readState.seqNum;
    return plaintext;
}

void TLSRecordLayer::setReadKeys(const std::vector<uint8_t>& key, const std::vector<uint8_t>& ivKey)
{
    validateKeyMaterial(key, ivKey);
    _readState.key = key;
    _readState.iv = ivKey;
    _readState.seqNum = 0;
}

void TLSRecordLayer::setWriteKeys(const std::vector<uint8_t>& key, const std::vector<uint8_t>& ivKey)
{
    validateKeyMaterial(key, ivKey);
    _writeState.key = key;
    _writeState.iv = ivKey;
    _writeState.seqNum = 0;
}

void TLSRecordLayer::resetReadSequence()
{
    _readState.seqNum = 0;
}

void TLSRecordLayer::resetWriteSequence()
{
    _writeState.seqNum = 0;
}

void TLSRecordLayer::resetSequences()
{
    resetReadSequence();
    resetWriteSequence();
}

void TLSRecordLayer::validateKeyMaterial(const std::vector<uint8_t>& key, const std::vector<uint8_t>& ivKey)
{
    if (key.size() != types::vars::AES_KEY_SIZE)
    {
        throw std::invalid_argument("Unsupported key size, expected 32 bytes");
    }
    if (ivKey.size() != types::vars::AES_IV_KEY_SIZE)
    {
        throw std::invalid_argument("Unsupported IV size, expected 12 bytes");
    }
}

std::vector<uint8_t> TLSRecordLayer::computeNonce(const CipherState& state)
{
    if (state.iv.size() != types::vars::AES_IV_KEY_SIZE)
    {
        throw std::invalid_argument("Unsupported IV size, expected 12 bytes");
    }

    std::vector<uint8_t> nonce(types::vars::AES_IV_KEY_SIZE);
    uint8_t seqBytes[8];
    for (int i = 0; i < 8; ++i)
    {
        seqBytes[7 - i] = static_cast<uint8_t>((state.seqNum >> (8 * i)) & 0xFF);
    }

    for (size_t i = 0; i < 12; ++i)
    {
        if (i < 4)
        {
            nonce[i] = state.iv[i];
        }
        else
        {
            nonce[i] = state.iv[i] ^ seqBytes[i - 4];
        }
    }
    return nonce;
}
