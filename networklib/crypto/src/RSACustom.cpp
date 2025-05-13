#include <RSACustom.h>
#include <SHA256Custom.h>

RSACustom::RSACustom()
{
    _rng.seed(std::chrono::steady_clock::now().time_since_epoch().count());
}

bmp::cpp_int RSACustom::modPow(const bmp::cpp_int& base, const bmp::cpp_int& exp, const bmp::cpp_int& mod)
{
    bmp::cpp_int baseIn{base};
    bmp::cpp_int expIn{exp};
    bmp::cpp_int result = 1;
    baseIn = baseIn % mod;
    while (expIn > 0)
    {
        if (expIn % 2 == 1)
        {
            result = (result * baseIn) % mod;
        }
        baseIn = (baseIn * baseIn) % mod;
        expIn /= 2;
    }
    return result;
}

bmp::cpp_int RSACustom::gcd(const bmp::cpp_int& a, const bmp::cpp_int& b)
{
    bmp::cpp_int aIn{a};
    bmp::cpp_int bIn{b};
    while (bIn != 0)
    {
        bmp::cpp_int t = bIn;
        bIn = aIn % bIn;
        aIn = t;
    }
    return aIn;
}

bmp::cpp_int RSACustom::modInverse(const bmp::cpp_int& val, const bmp::cpp_int& mod)
{
    bmp::cpp_int valIn{val};
    bmp::cpp_int modIn{mod};
    bmp::cpp_int m0 = modIn;
    bmp::cpp_int t;
    bmp::cpp_int q;
    bmp::cpp_int x0 = 0;
    bmp::cpp_int x1 = 1;
    while (valIn > 1)
    {
        q = valIn / modIn;
        t = modIn;
        modIn = valIn % modIn;
        valIn = t;
        t = x0;
        x0 = x1 - q * x0;
        x1 = t;
    }
    if (x1 < 0)
    {
        x1 += m0;
    }
    return x1;
}

bmp::cpp_int RSACustom::generatePrime(const int32_t& bits)
{
    return generatePrime(bits, _rng);
}

bmp::cpp_int RSACustom::generatePrime(const int32_t& bits, std::mt19937& rng)
{
    std::uniform_int_distribution<uint64_t> dist(0, std::numeric_limits<uint64_t>::max());
    while (true)
    {
        bmp::cpp_int candidate = 0;
        for (int i = 0; i < bits; i += 64)
        {
            candidate <<= 64;
            candidate += dist(rng);
        }
        candidate |= bmp::cpp_int(1);  // make odd
        candidate |= bmp::cpp_int(1) << (bits - 1);  // ensure MSB is 1
        if (isPrime(candidate, 10, rng))
        {
            return candidate;
        }
    }
}

bool RSACustom::isPrime(const bmp::cpp_int& n, const int32_t& k)
{
    return isPrime(n, k, _rng);
}

bool RSACustom::isPrime(const bmp::cpp_int& n, const int32_t& k, std::mt19937& rng)
{
    if (n < 2)
    {
        return false;
    }
    if (n == 2 || n == 3)
    {
        return true;
    }
    if (n % 2 == 0)
    {
        return false;
    }

    bmp::cpp_int s = 0;
    bmp::cpp_int d = n - 1;
    while (d % 2 == 0)
    {
        d /= 2;
        ++s;
    }

    std::uniform_int_distribution<uint64_t> dist(2, 1 << 20);
    for (int32_t i = 0; i < k; ++i)
    {
        bmp::cpp_int a = dist(rng);
        bmp::cpp_int x = modPow(a, d, n);
        if (x == 1 || x == n - 1)
        {
            continue;
        }
        bool cont = false;
        for (bmp::cpp_int r = 1; r < s; ++r)
        {
            x = modPow(x, 2, n);
            if (x == n - 1)
            {
                cont = true;
                break;
            }
        }
        if (cont)
        {
            continue;
        }
        return false;
    }
    return true;
}

void RSACustom::generateKeys(const uint32_t& keySize)
{
#ifdef _DEBUG
    std::cout << "Generating " << KEY_SIZE << "-bit RSACustom key...\n";
#endif
    _keySize = keySize;
    _prime_p = generatePrime(_keySize / 2);
    _prime_q = generatePrime(_keySize / 2);
    while (_prime_q == _prime_p)
    {
        _prime_q = generatePrime(_keySize / 2);
    }

    _moduls_n = _prime_p * _prime_q;
    _totient_phi = (_prime_p - 1) * (_prime_q - 1);
    _public_exponent_e = 65537;
    if (gcd(_public_exponent_e, _totient_phi) != 1)
    {
        _public_exponent_e = 3;
    }
    _private_exponent_d = modInverse(_public_exponent_e, _totient_phi);

#ifdef _DEBUG
    std::cout << "[generateKeys] Public Key (e, n):\n" << _public_exponent_e << "\n" << _moduls_n << "\n";
    std::cout << "[generateKeys] Private Key (d, n):\n" << _private_exponent_d << "\n" << _moduls_n << "\n";
#endif
}

std::vector<uint8_t> RSACustom::pkcs1v15_pad(const std::string& message, const size_t& msgSize)
{
    const std::vector<uint8_t> data{message.begin(), message.end()};
    return pkcs1v15_pad(data, msgSize, _rng);
}

std::vector<uint8_t> RSACustom::pkcs1v15_pad(const std::vector<uint8_t>& data, const size_t& msgSize)
{
    return pkcs1v15_pad(data, msgSize, _rng);
}

std::vector<uint8_t> RSACustom::pkcs1v15_pad(const std::vector<uint8_t>& data, const size_t& msgSize, std::mt19937& rng)
{
    constexpr uint8_t minPadSize{11};
    if (data.size() > msgSize - minPadSize)
    {
        throw std::runtime_error("Message too long");
    }
    std::vector<uint8_t> padded(msgSize);
    padded[0] = 0x00;
    padded[1] = 0x02;

    std::uniform_int_distribution<uint8_t> dist(1, 255);
    size_t ps_len = msgSize - data.size() - 3;
    for (size_t i = 0; i < ps_len; ++i)
    {
        uint8_t val = 0;
        do
        {
            val = dist(rng);
        }
        while (val == 0);
        padded[2 + i] = val;
    }
    padded[2 + ps_len] = 0x00;
    std::copy(data.begin(), data.end(), padded.begin() + 3 + ps_len);
    return padded;
}

std::vector<uint8_t> RSACustom::unpad(const std::vector<uint8_t>& padded)
{
    constexpr uint8_t minPadSize{11};
    if (padded.size() < minPadSize || padded[0] != 0x00 || padded[1] != 0x02)
    {
        throw std::runtime_error("Invalid padding");
    }
    size_t index = 2;
    while (index < padded.size() && padded[index] != 0x00)
    {
        ++index;
    }
    if (index >= padded.size() - 1)
    {
        throw std::runtime_error("No zero separator in padding");
    }
    return std::vector<uint8_t>(padded.begin() + index + 1, padded.end());
}

bmp::cpp_int RSACustom::encrypt(const std::string& message)
{
    const std::vector<uint8_t> data{message.begin(), message.end()};
    return encrypt(data);
}

bmp::cpp_int RSACustom::encrypt(const std::vector<uint8_t>& data)
{
    const RSAPublicKey pubKey{._exponent=_public_exponent_e, ._modulus=_moduls_n};
    return encrypt(data, pubKey);
}

boost::multiprecision::cpp_int RSACustom::encrypt(const std::vector<uint8_t>& data, const RSAPublicKey& publicKey)
{
    bmp::cpp_int m;
    import_bits(m, data.begin(), data.end(), 8, false);

#ifdef _DEBUG
    std::cout << "[encrypt] Public Key (e, n):\n" << publicKey._exponent << "\n" << publicKey._modulus << std::endl;
#endif

    return modPow(m, publicKey._exponent, publicKey._modulus);
}

std::vector<uint8_t> RSACustom::decrypt(const bmp::cpp_int& cipher) const
{
#ifdef _DEBUG
    std::cout << "[decrypt] Private Key (d, n):\n" << _private_exponent_d << "\n" << _moduls_n << std::endl;
#endif
    bmp::cpp_int m = modPow(cipher, _private_exponent_d, _moduls_n);
    std::vector<uint8_t> bytes;
    export_bits(m, std::back_inserter(bytes), 8, false);
    return bytes;
}

// @todo: test
void RSACustom::encryptFile(const std::string& inputPath, const std::string& outputPath)
{
    std::ifstream inFile(inputPath, std::ios::binary);
    if (!inFile)
    {
        throw std::runtime_error("Failed to open input file: " + inputPath);
    }

    std::vector<uint8_t> data((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());

    bmp::cpp_int cipher = encrypt(data);

    // Сохранить cpp_int как байты
    std::vector<uint8_t> cipherBytes;
    export_bits(cipher, std::back_inserter(cipherBytes), 8);

    std::ofstream outFile(outputPath, std::ios::binary);
    if (!outFile)
    {
        throw std::runtime_error("Failed to open output file: " + outputPath);
    }
    outFile.write(reinterpret_cast<const char*>(cipherBytes.data()), cipherBytes.size());
}

// @todo: test
void RSACustom::decryptFile(const std::string& inputPath, const std::string& outputPath) const
{
    std::ifstream inFile(inputPath, std::ios::binary);
    if (!inFile)
    {
        throw std::runtime_error("Failed to open input file: " + inputPath);
    }

    std::vector<uint8_t> buffer((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());

    bmp::cpp_int cipher;
    import_bits(cipher, buffer.begin(), buffer.end(), 8);

    std::vector<uint8_t> decrypted = decrypt(cipher);

    std::ofstream outFile(outputPath, std::ios::binary);
    if (!outFile)
    {
        throw std::runtime_error("Failed to open output file: " + outputPath);
    }
    outFile.write(reinterpret_cast<const char*>(decrypted.data()), decrypted.size());
}

bmp::cpp_int RSACustom::sign(const std::vector<uint8_t>& data) const
{
    auto hash = sha256(data);
    bmp::cpp_int hash_int;
    import_bits(hash_int, hash.begin(), hash.end(), 8, false);
    return modPow(hash_int, _private_exponent_d, _moduls_n);
}

bool RSACustom::verify(const std::vector<uint8_t>& data, const bmp::cpp_int& signature) const
{
    auto hash = sha256(data);
    bmp::cpp_int hash_int;
    import_bits(hash_int, hash.begin(), hash.end(), 8, false);

    bmp::cpp_int decrypted_sig = modPow(signature, _public_exponent_e, _moduls_n);

    return decrypted_sig == hash_int;
}

RSAPublicKey RSACustom::getPublicKey() const
{
    return RSAPublicKey{_public_exponent_e, _moduls_n};
}

void RSACustom::loadPublicKey(const RSAPublicKey& publicKey)
{
    _public_exponent_e = publicKey._exponent;
    _moduls_n = publicKey._modulus;
}