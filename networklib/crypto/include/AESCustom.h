// Author: https://github.com/SergeyBel/AES

#ifndef AES_H_
#define AES_H_

#include <iomanip>
#include <vector>

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

    uint8_t* EncryptECB(const uint8_t in[], uint32_t inLen, const uint8_t key[]);
    uint8_t* DecryptECB(const uint8_t in[], uint32_t inLen, const uint8_t key[]);
    uint8_t* EncryptCBC(const uint8_t in[], uint32_t inLen, const uint8_t key[], const uint8_t* iv);
    uint8_t* DecryptCBC(const uint8_t in[], uint32_t inLen, const uint8_t key[], const uint8_t* iv);
    uint8_t* EncryptCFB(const uint8_t in[], uint32_t inLen, const uint8_t key[], const uint8_t* iv);
    uint8_t* DecryptCFB(const uint8_t in[], uint32_t inLen, const uint8_t key[], const uint8_t* iv);

    std::vector<uint8_t> EncryptECB(std::vector<uint8_t> in, std::vector<uint8_t> key);
    std::vector<uint8_t> DecryptECB(std::vector<uint8_t> in, std::vector<uint8_t> key);
    std::vector<uint8_t> EncryptCBC(std::vector<uint8_t> in, std::vector<uint8_t> key, std::vector<uint8_t> iv);
    std::vector<uint8_t> DecryptCBC(std::vector<uint8_t> in, std::vector<uint8_t> key, std::vector<uint8_t> iv);
    std::vector<uint8_t> EncryptCFB(std::vector<uint8_t> in, std::vector<uint8_t> key, std::vector<uint8_t> iv);
    std::vector<uint8_t> DecryptCFB(std::vector<uint8_t> in, std::vector<uint8_t> key, std::vector<uint8_t> iv);

    void printHexArray(uint8_t a[], uint32_t n);

    void printHexVector(std::vector<uint8_t> a);

    static std::vector<uint8_t> generateRandomIV(size_t length = 16);
    static std::vector<uint8_t> generateRandomKey(size_t length);

private:
    static constexpr uint32_t Nb = 4;
    static constexpr uint32_t blockBytesLen = 4 * Nb * sizeof(uint8_t);

    uint32_t Nk;
    uint32_t Nr;

    void SubBytes(uint8_t state[4][Nb]);

    void ShiftRow(uint8_t state[4][Nb], uint32_t i,
        uint32_t n);  // shift row i on n positions

    void ShiftRows(uint8_t state[4][Nb]);

    uint8_t xtime(uint8_t b);  // multiply on x

    void MixColumns(uint8_t state[4][Nb]);

    void AddRoundKey(uint8_t state[4][Nb], uint8_t* key);

    void SubWord(uint8_t* a);

    void RotWord(uint8_t* a);

    void XorWords(uint8_t* a, uint8_t* b, uint8_t* c);

    void Rcon(uint8_t* a, uint32_t n);

    void InvSubBytes(uint8_t state[4][Nb]);

    void InvMixColumns(uint8_t state[4][Nb]);

    void InvShiftRows(uint8_t state[4][Nb]);

    void CheckLength(uint32_t len);

    void KeyExpansion(const uint8_t key[], uint8_t w[]);

    void EncryptBlock(const uint8_t in[], uint8_t out[], uint8_t* roundKeys);

    void DecryptBlock(const uint8_t in[], uint8_t out[], uint8_t* roundKeys);

    void XorBlocks(const uint8_t* a, const uint8_t* b, uint8_t* c, uint32_t len);

    std::vector<uint8_t> ArrayToVector(uint8_t* a, uint32_t len);

    uint8_t* VectorToArray(std::vector<uint8_t>& a);

    std::vector<uint8_t> PKCS7Pad(const std::vector<uint8_t>& data);
    std::vector<uint8_t> PKCS7Unpad(const std::vector<uint8_t>& data);
};

#endif