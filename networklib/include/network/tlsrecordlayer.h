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

    void resetSequence() { _seqNum = 0; }

private:
    AESCrypto _aead;
    std::vector<uint8_t> _ivKey;
    uint64_t _seqNum;

    std::vector<uint8_t> computeNonce() const;
};

#endif  // TLSRECORDLAYER_H
