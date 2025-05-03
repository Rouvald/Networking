#include "SHA256Custom.h"

#include <cstdint>

#include <AESCustom.h>
#include <RSACustom.h>
#include <manager.h>

void testRSA()
{
    RSACustom rsa = RSACustom();
    std::string msg{"Hello world!!!!?"};
    bmp::cpp_int ciph = rsa.encrypt(msg);
    std::cout << "Encrypted: " << ciph << "\n";

    std::string decrypted = rsa.decrypt(ciph);
    std::cout << "Decrypted: " << decrypted << "\n";

    // with sign
    std::string message = "Hello custom TLS! Test";

    bmp::cpp_int signature = rsa.sign(message);
    std::cout << "Signature:\n" << signature << "\n\n";

    bool isValid = rsa.verify(message, signature);
    std::cout << "Signature valid? " << (isValid ? "YES" : "NO") << "\n";

    std::string tampered = message + "!";
    bool fakeValid = rsa.verify(tampered, signature);
    std::cout << "Tampered valid? " << (fakeValid ? "YES" : "NO") << "\n";
}

void testSHA()
{
    const std::string testMsg{"Test message wuth some symbols !!?"};
    auto hash_1 = sha256(testMsg);
    std::cout << "hash_1 - " << hash_1 << '\n';
    auto hash_2 = sha256(testMsg);
    std::cout << "hash_2 - " << hash_2 << '\n';
}

void testAES(const std::string& label, AESKeyLength keyLength, size_t keySize)
{
    std::string plainText = "AES test message for CBC mode!";
    std::vector<unsigned char> data(plainText.begin(), plainText.end());

    std::vector<unsigned char> key = AESCustom::generateRandomKey(keySize);
    std::vector<unsigned char> iv = AESCustom::generateRandomIV();

    AESCustom aes(keyLength);

    std::cout << "\n=== " << label << " ===\n";
    std::cout << "Plaintext:\n";
    aes.printHexVector(data);

    std::cout << "Random Key:\n";
    aes.printHexVector(key);

    std::cout << "Random IV:\n";
    aes.printHexVector(iv);

    auto encrypted = aes.EncryptCBC(data, key, iv);
    std::cout << "Encrypted:\n";
    aes.printHexVector(encrypted);

    auto decrypted = aes.DecryptCBC(encrypted, key, iv);
    std::cout << "Decrypted:\n";
    aes.printHexVector(decrypted);

    std::string decryptedStr(decrypted.begin(), decrypted.end());
    std::cout << "As string: " << decryptedStr << "\n";
}

void testAESs()
{
    testAES("AES-128 CBC", AESKeyLength::AES_128, 16);
    testAES("AES-256 CBC", AESKeyLength::AES_256, 32);
}

int32_t main(int32_t argc, char** argv)
{
    (void)argc;
    (void)argv;

    // Network
    /*basio::io_context io;
    Manager mng(io.get_executor(), "google.com");
    mng.connect();
    mng.disconnect();
    mng.connect();*/

    // RSA
    testRSA();

    // sha
    testSHA();

    // AES
    testAESs();

    return EXIT_SUCCESS;
}