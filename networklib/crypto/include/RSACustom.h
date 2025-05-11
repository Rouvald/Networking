#ifndef RSACUSTOM_H
#define RSACUSTOM_H

#include <RSAPublicKey.h>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/random.hpp>
#include <chrono>
#include <fstream>
#include <random>
#include <vector>

namespace bmp = boost::multiprecision;

class RSACustom
{
public:
    RSACustom();
    ~RSACustom() = default;
    RSACustom(const RSACustom&) = default;
    RSACustom& operator=(const RSACustom&) = default;
    RSACustom(RSACustom&&) = default;
    RSACustom& operator=(RSACustom&&) = default;

    enum class RSAKeyLength : uint16_t
    {
        RSA_1024 = 1024,
        RSA_2048 = 2048,
        RSA_4096 = 4096
    };

    // #note: string crypt
    bmp::cpp_int encrypt(const std::string& message);

    // @note: base logic
    bmp::cpp_int encrypt(const std::vector<uint8_t>& data);
    std::vector<uint8_t> decrypt(const bmp::cpp_int& cipher) const;

    // @note: static crypt
    static boost::multiprecision::cpp_int encrypt(const std::vector<uint8_t>& data, const RSAPublicKey& publicKey);

    // @note: file crypt
    void encryptFile(const std::string& inputPath, const std::string& outputPath);
    void decryptFile(const std::string& inputPath, const std::string& outputPath) const;

    // @note: sign logic
    bmp::cpp_int sign(const std::vector<uint8_t>& data) const;
    bool verify(const  std::vector<uint8_t>& data, const bmp::cpp_int& signature) const;

    void generateKeys(const uint32_t& keySize);

    RSAPublicKey getPublicKey() const;
    void loadPublicKey(const RSAPublicKey& publicKey);

private:
    bmp::cpp_int generatePrime(const int32_t& bits);
    bool isPrime(const bmp::cpp_int& n, const int32_t& k);

    static bmp::cpp_int modPow(const bmp::cpp_int& base, const bmp::cpp_int& exp, const bmp::cpp_int& mod);
    static bmp::cpp_int gcd(const bmp::cpp_int& a, const bmp::cpp_int& b);
    static bmp::cpp_int modInverse(const bmp::cpp_int& val, const bmp::cpp_int& mod);
    static bmp::cpp_int generatePrime(const int32_t& bits, std::mt19937& rng);
    static bool isPrime(const bmp::cpp_int& n, const int32_t& k, std::mt19937& rng);

    // @note: string padding
    std::vector<uint8_t> pkcs1v15_pad(const std::string& message, const size_t& msgSize);

    // @note: base padding logic
    std::vector<uint8_t> pkcs1v15_pad(const std::vector<uint8_t>& data, const size_t& msgSize);

    // @note: static padding
    static std::vector<uint8_t> pkcs1v15_pad(const std::vector<uint8_t>& data, const size_t& msgSize, std::mt19937& rng);
    static std::vector<uint8_t> unpad(const std::vector<uint8_t>& padded);

    bmp::cpp_int _prime_p,  // first big value
        _prime_q,  // second big value
        _moduls_n,  // n = p * q
        _totient_phi,  // φ(n) = (p-1)*(q-1)
        _public_exponent_e,  // public exp
        _private_exponent_d;  // private exp
    std::mt19937 _rng;
    uint32_t _keySize{};
};

#endif  // RSACUSTOM_H
