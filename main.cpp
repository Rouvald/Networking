#include "SHA256Custom.h"

#include <cstdint>

#include <AESCustom.h>
#include <RSACustom.h>
#include <manager.h>
#include <HandshakeContext.h>
#include <SessionCipher.h>

constexpr uint8_t minStringLength{10};
constexpr uint8_t maxStringLength{50};

void printData(const std::vector<uint8_t>& data)
{
    std::cout << "[printData]: "
              << "\t";
    for (const auto& elem : data)
    {
        std::cout << elem << " ";
    }
    std::cout << std::endl;
}

static uint32_t generateRandomStringLength(const uint32_t& min, const uint32_t& max)
{
    std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<> lenDist(min, max);
    return lenDist(rng);
}

static std::string generateRandomString(const uint32_t& length)
{
    std::cout << "[generateRandomString] length - " << length << std::endl;
    static const std::string characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    static std::mt19937 rng(std::random_device{}());
    static std::uniform_int_distribution<> dist(0, characters.size() - 1);

    std::string result;
    result.reserve(length);

    for (uint32_t i = 0; i < length; ++i)
    {
        result += characters[dist(rng)];
    }
    std::cout << "[generateRandomString] result string - " << result << std::endl;
    return result;
}

static void testRSA()
{
    RSACustom rsa = RSACustom();
    rsa.generateKeys(static_cast<uint32_t>(RSACustom::RSAKeyLength::RSA_2048));

    const std::string msg{generateRandomString(generateRandomStringLength(minStringLength, maxStringLength))};
    const bmp::cpp_int ciph = rsa.encrypt(msg);
    std::cout << "Encrypted: " << ciph << "\n";

    const std::vector<uint8_t> decrypted = rsa.decrypt(ciph);
    printData(decrypted);

    // with sign
    std::string message{generateRandomString(generateRandomStringLength(minStringLength, maxStringLength))};
    std::vector<uint8_t> data{message.begin(), message.end()};

    const bmp::cpp_int signature = rsa.sign(data);
    std::cout << "Signature:\n" << signature << "\n\n";

    const bool isValid = rsa.verify(data, signature);
    std::cout << "Signature valid? " << (isValid ? "YES" : "NO") << "\n";

    data.push_back('!');
    const bool fakeValid = rsa.verify(data, signature);
    std::cout << "Tampered valid? " << (fakeValid ? "YES" : "NO") << "\n";
}

static void testRSA_AES()
{
    RSACustom rsa = RSACustom();
    rsa.generateKeys(static_cast<uint32_t>(RSACustom::RSAKeyLength::RSA_2048));

    const RSAPublicKey pub{rsa.getPublicKey()};

    const std::vector<uint8_t> data{AESCustom::generateRandomKey(CIPHER_256_KEY_SIZE)};
    const bmp::cpp_int ciph = rsa.encrypt(data, pub);
    printData(data);
    std::cout << "Encrypted: " << ciph << "\n";

    const std::vector<uint8_t> decrypted = rsa.decrypt(ciph);
    printData(decrypted);
}

static void testSHA()
{
    const std::string testMsg{generateRandomString(generateRandomStringLength(minStringLength, maxStringLength))};
    const std::vector<uint8_t> data{testMsg.begin(), testMsg.end()};
    auto hash_1 = sha256(data);
    std::cout << "hash_1 - " << '\n';
    printData(hash_1);
    auto hash_2 = sha256(data);
    std::cout << "hash_2 - " << '\n';
    printData(hash_2);
}

static void testAES(const std::string& label, AESKeyLength keyLength, size_t keySize)
{
    std::string plainText{generateRandomString(generateRandomStringLength(minStringLength, maxStringLength))};
    const std::vector<uint8_t> data(plainText.begin(), plainText.end());

    const std::vector<uint8_t> key = AESCustom::generateRandomKey(keySize);
    const std::vector<uint8_t> iv = AESCustom::generateRandomIV();

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

    const std::string decryptedStr(decrypted.begin(), decrypted.end());
    std::cout << "As string: " << decryptedStr << "\n";
}

static void testAESs()
{
    testAES("AES-128 CBC", AESKeyLength::AES_128, CIPHER_128_KEY_SIZE);
    testAES("AES-256 CBC", AESKeyLength::AES_256, CIPHER_256_KEY_SIZE);
}

static void testHandshake()
{
    HandshakeContext serverCtx(false);
    RSAPublicKey serverPubKey = serverCtx.getPublicKey();

    std::cout << "[Server] generate RSA\n";

    HandshakeContext clientCtx(true);
    clientCtx.generateSessionKey();

    std::cout << "[Client] generate session AES\n";

    auto encryptedKey = clientCtx.encryptSessionKeyWithServerRSA(serverPubKey);

    std::cout << "[Client] encrypt AES\n";

    // std::cout << "[TEST] encryptedKey - " << encryptedKey << '\n';

    serverCtx.decryptSessionKeyFromClient(encryptedKey);

    std::cout << "[Server] decrypt AES \n";

    const auto& clientKey = clientCtx.getSessionKey();
    const auto& serverKey = serverCtx.getSessionKey();

    const bool keysMatch = (clientKey == serverKey);

    std::cout << "Seesion keys are " << (keysMatch ? "equal" : "different") << "\n";
}

static void testSecureSession(const int32_t& strLen)
{
    std::cout << "=== Secure Session ===\n";

    HandshakeContext serverHandshake(false);
    const RSAPublicKey serverPubKey = serverHandshake.getPublicKey();
    std::cout << "[Server] Generated RSA key pair\n";

    HandshakeContext clientHandshake(true);
    clientHandshake.generateSessionKey();
    std::cout << "[Client] Generated AES session key\n";

    auto encryptedSessionKey = clientHandshake.encryptSessionKeyWithServerRSA(serverPubKey);
    std::cout << "[Client] Encrypted AES key with server's public RSA key\n";

    serverHandshake.decryptSessionKeyFromClient(encryptedSessionKey);
    std::cout << "[Server] Decrypted AES session key from client\n";

    SessionCipher clientCipher;
    clientCipher.setKey(clientHandshake.getSessionKey());

    SessionCipher serverCipher;
    serverCipher.setKey(serverHandshake.getSessionKey());
    serverCipher.setIV(clientCipher.getIV());  // sync IV

    std::string plaintext;
    if (strLen == -1)
    {
        plaintext = generateRandomString(generateRandomStringLength(minStringLength, maxStringLength));
    }
    else
    {
        plaintext = generateRandomString(strLen);
    }
    const std::vector<uint8_t> data(plaintext.begin(), plaintext.end());

    auto encrypted = clientCipher.encrypt(data);
    std::cout << "[Client] Encrypted message sent to server\n";

    auto decrypted = serverCipher.decrypt(encrypted);
    const std::string recovered(decrypted.begin(), decrypted.end());

    std::cout << "[Server] Decrypted message: " << recovered << "\n";

    const bool keysMatch = (clientHandshake.getSessionKey() == serverHandshake.getSessionKey());
    std::cout << "[Handshake] Session keys match: " << (keysMatch ? "YES" : "NO") << "\n";
}

int32_t main(int32_t argc, char** argv)
{
    (void)argc;
    (void)argv;

    try
    {

        // Network
        /*basio::io_context io;
        Manager mng(io.get_executor(), "google.com");
        mng.connect();
        mng.disconnect();
        mng.connect();*/

        std::cout << std::endl << "===================================================================" << std::endl << std::endl;

        // RSA
        // testRSA();
        /*for (uint32_t i = 1; i < 100; ++i)
        {
            testRSA_AES();
        }*/

        std::cout << std::endl << "===================================================================" << std::endl << std::endl;

        // sha
        // testSHA();

        std::cout << std::endl << "===================================================================" << std::endl << std::endl;

        // AES
        // testAESs();

        std::cout << std::endl << "===================================================================" << std::endl << std::endl;

        // Handshake
        // testHandshake();

        // session
        // testSecureSession();
        for (uint32_t i = 1; i < 200; ++i)
        {
            testSecureSession(i);
        }
    }
    catch (const std::exception& e)
    {
        std::cout << "Error: " << e.what() << std::endl;
    }

    return EXIT_SUCCESS;
}