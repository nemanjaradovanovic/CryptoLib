#include "rsa.hpp"
#include "bigint_utils.hpp"
#include "prime_utils.hpp"
#include "oaep.hpp"
#include "hash_utils.hpp"
#include <stdexcept>

namespace CryptoLib {

    RSAKeyPair RSA::generate_keys(int bits) {
        if (bits < 512) throw std::invalid_argument("RSA key size too small; use >= 1024.");

        int half = bits / 2;
        BigInt p = generate_prime(half);
        BigInt q = generate_prime(half);
        while (q == p) { q = generate_prime(half); }

        BigInt n = p * q;
        BigInt phi = (p - 1) * (q - 1);

        BigInt e = 65537;
        BigInt x, y;
        BigInt g = egcd(e, phi, x, y);
        if (g != 1) {
            e = 3;
            while (true) {
                g = egcd(e, phi, x, y);
                if (g == 1) break;
                e += 2;
            }
        }

        BigInt d = modinv(e, phi);

        RSAKeyPair kp;
        kp.public_key = PublicKey{ n, e };
        kp.private_key = PrivateKey{ n, d };
        return kp;
    }

    std::vector<std::uint8_t> RSA::encrypt(const std::vector<std::uint8_t>& plaintext,
                                           const PublicKey& pub) {
        if (pub.n == 0 || pub.e == 0) throw std::invalid_argument("Invalid public key.");
        BigInt m = bytes_to_bigint(plaintext);
        if (m >= pub.n) throw std::invalid_argument("Plaintext too large for modulus.");
        BigInt c = modexp(m, pub.e, pub.n);
        return bigint_to_bytes(c);
    }

    std::vector<std::uint8_t> RSA::decrypt(const std::vector<std::uint8_t>& ciphertext,
                                           const PrivateKey& priv) {
        if (priv.n == 0 || priv.d == 0) throw std::invalid_argument("Invalid private key.");
        BigInt c = bytes_to_bigint(ciphertext);
        if (c >= priv.n) throw std::invalid_argument("Ciphertext >= modulus.");
        BigInt m = modexp(c, priv.d, priv.n);
        return bigint_to_bytes(m);
    }

    std::vector<std::uint8_t> RSA::encrypt_string(const std::string& plaintext,
                                                  const PublicKey& pub) {
        const auto k = bigint_to_bytes(pub.n).size();
        const std::vector<std::uint8_t> msg(plaintext.begin(), plaintext.end());
        auto em = oaep_encode(msg, k);
        return encrypt(em, pub);
    }

    std::string RSA::decrypt_to_string(const std::vector<std::uint8_t>& ciphertext,
                                       const PrivateKey& priv) {
        const auto k = bigint_to_bytes(priv.n).size();
        auto em = decrypt(ciphertext, priv);
        if (em.size() < k) {
            std::vector<std::uint8_t> padded(k - em.size(), 0x00);
            padded.insert(padded.end(), em.begin(), em.end());
            em.swap(padded);
        } else if (em.size() > k) {
            throw std::runtime_error("Decrypted block larger than modulus length");
        }
        auto msg = oaep_decode(em, k);
        return std::string(msg.begin(), msg.end());
    }

    std::vector<std::uint8_t> RSA::sign(const std::string& message, const PrivateKey& priv) {
        std::vector<std::uint8_t> msg_bytes(message.begin(), message.end());
        auto hash = sha256(msg_bytes);

        BigInt m = bytes_to_bigint(hash);
        if (m >= priv.n) throw std::invalid_argument("Hash too large for modulus");

        BigInt s = modexp(m, priv.d, priv.n);
        return bigint_to_bytes(s);
    }

    bool RSA::verify(const std::string& message,
                     const std::vector<std::uint8_t>& signature,
                     const PublicKey& pub) {
        std::vector<std::uint8_t> msg_bytes(message.begin(), message.end());
        auto hash = sha256(msg_bytes);

        BigInt s = bytes_to_bigint(signature);
        if (s >= pub.n) return false;

        BigInt m = modexp(s, pub.e, pub.n);
        auto recovered = bigint_to_bytes(m);

        // Poravnaj dužinu
        if (recovered.size() < hash.size()) {
            std::vector<std::uint8_t> padded(hash.size() - recovered.size(), 0x00);
            padded.insert(padded.end(), recovered.begin(), recovered.end());
            recovered.swap(padded);
        }

        return recovered == hash;
    }

} // namespace CryptoLib