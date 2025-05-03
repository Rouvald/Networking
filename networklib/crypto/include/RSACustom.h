#ifndef RSACUSTOM_H
#define RSACUSTOM_H

#include <boost/multiprecision/cpp_int.hpp>
#include <boost/random.hpp>
#include <chrono>
#include <fstream>
#include <iostream>
#include <random>
#include <vector>

namespace bmp = boost::multiprecision;

class RSACustom
{
public:
    RSACustom();
    ~RSACustom() = default;
    RSACustom(const RSACustom&) = default;
    RSACustom& operator=(const RSACustom &) = default;
    RSACustom(RSACustom &&) = default;
    RSACustom & operator=(RSACustom &&) = default;

    bmp::cpp_int encrypt(const std::string& message);
    std::string decrypt(const bmp::cpp_int& cipher);
    void encryptFile(const std::string& inputPath, const std::string& outputPath);
    void decryptFile(const std::string& inputPath, const std::string& outputPath);
    bmp::cpp_int sign(const std::string& message);
    bool verify(const std::string& message, const bmp::cpp_int& signature);

private:
    static bmp::cpp_int modPow(const bmp::cpp_int& base, const bmp::cpp_int& exp, const bmp::cpp_int& mod);
    static bmp::cpp_int gcd(const bmp::cpp_int& a, const bmp::cpp_int& b);
    static bmp::cpp_int modInverse(const bmp::cpp_int& val, const bmp::cpp_int& mod);
    bmp::cpp_int generatePrime(const int32_t& bits);
    bool isPrime(const bmp::cpp_int& n, const int32_t& k = 10);
    void generateKeys();
    std::vector<uint8_t> pkcs1v15_pad(const std::string& message, size_t k);
    std::string unpad(const std::vector<uint8_t>& padded);

    bmp::cpp_int _prime_p,  // first big value
        _prime_q,  // second big value
        _moduls_n,  // n = p * q
        _totient_phi,  // φ(n) = (p-1)*(q-1)
        _public_exponent_e,  // public exp
        _private_exponent_d;  // private exp
    std::mt19937 rng; // random generator
};

#endif  // RSACUSTOM_H
