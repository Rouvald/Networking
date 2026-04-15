#ifndef TLSRECORDLAYER_H
#define TLSRECORDLAYER_H

#include <cstdint>
#include <vector>
#include "utils/types.h"
#include "crypto/aescrypto.h"

class TLSRecordLayer
{
public:
    TLSRecordLayer(const std::vector<uint8_t>& key, const std::vector<uint8_t>& ivKey);
    types::TLSCiphertext encode(uint8_t type, uint16_t legacyVersion, const std::vector<uint8_t>& plaintext);
    std::vector<uint8_t> decode(const types::TLSCiphertext& record);

    void setReadKeys(const std::vector<uint8_t>& key, const std::vector<uint8_t>& ivKey);
    void setWriteKeys(const std::vector<uint8_t>& key, const std::vector<uint8_t>& ivKey);
    void resetReadSequence();
    void resetWriteSequence();
    void resetSequences();

private:
    struct CipherState
    {
        std::vector<uint8_t> key;
        std::vector<uint8_t> iv;
        uint64_t seqNum{0};
    };

    CipherState _readState;
    CipherState _writeState;

    static void validateKeyMaterial(const std::vector<uint8_t>& key, const std::vector<uint8_t>& ivKey);
    static std::vector<uint8_t> computeNonce(const CipherState& state);
};

#endif  // TLSRECORDLAYER_H
