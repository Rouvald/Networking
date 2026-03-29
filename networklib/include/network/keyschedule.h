#ifndef KEYSCHEDULE_H
#define KEYSCHEDULE_H

#include <cstdint>
#include <vector>
#include <string>
#include "utils/types.h"

class HKDF
{
public:
    static std::vector<uint8_t> extract(const std::vector<uint8_t>& salt, const std::vector<uint8_t>& ikm);
    static std::vector<uint8_t> expand(const std::vector<uint8_t>& prk, const std::vector<uint8_t>& info, size_t length);
    static std::vector<uint8_t> expandLabel(
        const std::vector<uint8_t>& secret, const std::string& label, const std::vector<uint8_t>& context, size_t length);
};
inline std::vector<uint8_t> deriveEarlySecret(const std::vector<uint8_t>& psk)
{
    return HKDF::extract(std::vector<uint8_t>(), psk);
}
inline std::vector<uint8_t> deriveHandshakeSecret(const std::vector<uint8_t>& earlySecret, const std::vector<uint8_t>& sharedSecret)
{
    return HKDF::extract(earlySecret, sharedSecret);
}
inline std::vector<uint8_t> deriveTrafficSecret(
    const std::vector<uint8_t>& secret, const std::string& label, const std::vector<uint8_t>& transcriptHash)
{
    return HKDF::expandLabel(secret, label, transcriptHash, types::vars::SHA256_KEY_SIZE);
}
inline std::vector<uint8_t> deriveMasterSecret(const std::vector<uint8_t>& handshakeSecret)
{
    return HKDF::extract(handshakeSecret, std::vector<uint8_t>());
}

#endif  // KEYSCHEDULE_H
