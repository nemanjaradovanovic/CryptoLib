#pragma once
#include <vector>
#include <string>
#include <cstdint>
#include "bigint_utils.hpp"

namespace CryptoLib {

    struct PublicKey {
        BigInt n;
        BigInt e;
    };

    struct PrivateKey {
        BigInt n;
        BigInt d;
    };

    struct RSAKeyPair {
        PublicKey public_key;
        PrivateKey private_key;
    };

    class RSA {
    public:
        static RSAKeyPair generate_keys(int bits);

        static std::vector<std::uint8_t> encrypt(const std::vector<std::uint8_t>& plaintext,
                                                 const PublicKey& pub);
        static std::vector<std::uint8_t> decrypt(const std::vector<std::uint8_t>& ciphertext,
                                                 const PrivateKey& priv);

        static std::vector<std::uint8_t> encrypt_string(const std::string& plaintext,
                                                        const PublicKey& pub);
        static std::string decrypt_to_string(const std::vector<std::uint8_t>& ciphertext,
                                             const PrivateKey& priv);

        // ➕ Digitalni potpis i verifikacija
        static std::vector<std::uint8_t> sign(const std::string& message, const PrivateKey& priv);
        static bool verify(const std::string& message,
                           const std::vector<std::uint8_t>& signature,
                           const PublicKey& pub);
    };

} // namespace CryptoLib