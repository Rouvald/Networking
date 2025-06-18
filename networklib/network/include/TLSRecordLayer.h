#ifndef TLSRECORDLAYER_H
#define TLSRECORDLAYER_H

#include <cstdint>
#include <vector>
#include <iobytes.h>
#include <AESCrypto.h>

class TLSRecordLayer
{
public:
    TLSRecordLayer(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv_key);
    TLSCiphertext encode(uint8_t type, uint16_t legacy_version, const std::vector<uint8_t>& plaintext);
    std::vector<uint8_t> decode(const TLSCiphertext& record);

    void reset_sequence() { _seq_num = 0; }

private:
    AESCrypto _aead;
    std::vector<uint8_t> _iv_key;
    uint64_t _seq_num;

    std::vector<uint8_t> compute_nonce() const;
};

#endif  // TLSRECORDLAYER_H
