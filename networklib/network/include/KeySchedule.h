#ifndef KEYSCHEDULE_H
#define KEYSCHEDULE_H

#include <cstdint>
#include <vector>
#include <string>
#include <UtilsCrypto.h>

class HKDF
{
public:
    static std::vector<uint8_t> extract(const std::vector<uint8_t>& salt, const std::vector<uint8_t>& ikm);
    static std::vector<uint8_t> expand(const std::vector<uint8_t>& prk, const std::vector<uint8_t>& info, size_t L);
    static std::vector<uint8_t> expandLabel(
        const std::vector<uint8_t>& secret, const std::string& label, const std::vector<uint8_t>& context, size_t length);
};
inline std::vector<uint8_t> deriveEarlySecret(const std::vector<uint8_t>& psk)
{
    return HKDF::extract(std::vector<uint8_t>(), psk);
}
inline std::vector<uint8_t> deriveHandshakeSecret(const std::vector<uint8_t>& early_secret, const std::vector<uint8_t>& shared_secret)
{
    return HKDF::extract(early_secret, shared_secret);
}
inline std::vector<uint8_t> deriveTrafficSecret(
    const std::vector<uint8_t>& secret, const std::string& label, const std::vector<uint8_t>& transcript_hash)
{
    return HKDF::expandLabel(secret, label, transcript_hash, UtilsCrypto::SHA256_KEY_SIZE);
}
inline std::vector<uint8_t> deriveMasterSecret(const std::vector<uint8_t>& handshake_secret)
{
    return HKDF::extract(handshake_secret, std::vector<uint8_t>());
}

#endif  // KEYSCHEDULE_H
