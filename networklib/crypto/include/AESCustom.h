// Author: https://github.com/SergeyBel/AES

#ifndef AES_H_
#define AES_H_

#include <cstddef>
#include <cstdint>
#include <vector>

constexpr uint8_t CIPHER_128_KEY_SIZE = 16;
constexpr uint8_t CIPHER_256_KEY_SIZE = 32;
constexpr uint8_t CIPHER_IV_SIZE = 16;

enum class AESKeyLength : uint8_t
{
    AES_128,
    AES_192,
    AES_256
};

class AESCustom
{
public:
    explicit AESCustom(const AESKeyLength& keyLength = AESKeyLength::AES_256);

    uint8_t* EncryptECB(const uint8_t inData[], uint32_t inLen, const uint8_t key[]);
    uint8_t* DecryptECB(const uint8_t inData[], uint32_t inLen, const uint8_t key[]);
    uint8_t* EncryptCBC(const uint8_t inData[], uint32_t inLen, const uint8_t key[], const uint8_t* ivKey);
    uint8_t* DecryptCBC(const uint8_t inData[], uint32_t inLen, const uint8_t key[], const uint8_t* ivKey);
    uint8_t* EncryptCFB(const uint8_t inData[], uint32_t inLen, const uint8_t key[], const uint8_t* ivKey);
    uint8_t* DecryptCFB(const uint8_t inData[], uint32_t inLen, const uint8_t key[], const uint8_t* ivKey);

    std::vector<uint8_t> EncryptECB(std::vector<uint8_t> inData, std::vector<uint8_t> key);
    std::vector<uint8_t> DecryptECB(std::vector<uint8_t> inData, std::vector<uint8_t> key);
    std::vector<uint8_t> EncryptCBC(const std::vector<uint8_t>& inData, std::vector<uint8_t> key, std::vector<uint8_t> ivKey);
    std::vector<uint8_t> DecryptCBC(std::vector<uint8_t> inData, std::vector<uint8_t> key, std::vector<uint8_t> ivKey);
    std::vector<uint8_t> EncryptCFB(std::vector<uint8_t> inData, std::vector<uint8_t> key, std::vector<uint8_t> ivKey);
    std::vector<uint8_t> DecryptCFB(std::vector<uint8_t> inData, std::vector<uint8_t> key, std::vector<uint8_t> ivKey);

    static void printHexArray(uint8_t arrData[], uint32_t arrSize);

    static void printHexVector(std::vector<uint8_t> a);

    static std::vector<uint8_t> generateRandomIV(size_t length = CIPHER_IV_SIZE);
    static std::vector<uint8_t> generateRandomKey(size_t length);

private:
    static constexpr uint32_t Nb = 4;
    static constexpr uint32_t blockBytesLen = 4 * Nb * sizeof(uint8_t);

    uint32_t Nk;
    uint32_t Nr;

    static void SubBytes(uint8_t state[4][Nb]);

    void ShiftRow(uint8_t state[4][Nb], uint32_t i,
        uint32_t n);  // shift row i on n positions

    void ShiftRows(uint8_t state[4][Nb]);

    static uint8_t xtime(uint8_t b);  // multiply on static x

    void MixColumns(uint8_t state[4][Nb]);

    static void AddRoundKey(uint8_t state[4][Nb], uint8_t* key);

    static void SubWord(uint8_t* data);

    static void RotWord(uint8_t* data);

    static void XorWords(uint8_t* dataFirst, uint8_t* dataSecond, uint8_t* dataThird);

    static void Rcon(uint8_t* data, uint32_t size);

    static void InvSubBytes(uint8_t state[4][Nb]);

    static void InvMixColumns(uint8_t state[4][Nb]);

    void InvShiftRows(uint8_t state[4][Nb]);

    void CheckLength(uint32_t len);

    void KeyExpansion(const uint8_t key[], uint8_t w[]) const;

    void EncryptBlock(const uint8_t inData[], uint8_t outData[], uint8_t* roundKeys);

    void DecryptBlock(const uint8_t inData[], uint8_t outData[], uint8_t* roundKeys);

    static void XorBlocks(const uint8_t* dataFirst, const uint8_t* dataSecond, uint8_t* dataThird, uint32_t len);

    static std::vector<uint8_t> ArrayToVector(uint8_t* arr, uint32_t size);

    static uint8_t* VectorToArray(std::vector<uint8_t>& vec);

    std::vector<uint8_t> PKCS7Pad(const std::vector<uint8_t>& data);
    std::vector<uint8_t> PKCS7Unpad(const std::vector<uint8_t>& data);
};

#endif