#include "prime_utils.hpp"
#include "random_utils.hpp"
#include "bigint_utils.hpp"
#include <vector>
#include <stdexcept>
#include <algorithm>

namespace CryptoLib {

    static BigInt bytes_to_bigint_be(const std::vector<std::uint8_t>& bytes) {
        BigInt x = 0;
        for (auto b : bytes) { x <<= 8; x += b; }
        return x;
    }

    BigInt random_bigint_bits(int bits) {
        if (bits <= 0) throw std::invalid_argument("random_bigint_bits: bits must be > 0");
        const int bytes = (bits + 7) / 8;
        std::vector<std::uint8_t> buf(bytes);
        csprng_bytes(buf);

        // Maskiraj višak bitova
        const int extra = bytes * 8 - bits;
        if (extra > 0) {
            std::uint8_t mask = static_cast<std::uint8_t>(0xFFu >> extra);
            buf[0] &= mask;
        }
        buf[0] |= 0x80;                   // MSB set -> tačna bit-dužina
        buf[bytes - 1] |= 0x01;           // odd

        return bytes_to_bigint_be(buf);
    }

    static bool miller_rabin_witness(const BigInt& a, const BigInt& n, const BigInt& d, int s) {
        BigInt x = modexp(a, d, n);
        if (x == 1 || x == n - 1) return false;
        for (int i = 1; i < s; ++i) {
            x = (x * x) % n;
            if (x == n - 1) return false;
        }
        return true; // composite
    }

    bool is_probable_prime(const BigInt& n, int rounds) {
        if (n < 2) return false;
        static const int smalls[] = {2,3,5,7,11,13,17,19,23,29,31,37};
        for (int p : smalls) {
            if (n == p) return true;
            if (n % p == 0) return n == p;
        }

        BigInt d = n - 1;
        int s = 0;
        while ((d & 1) == 0) { d >>= 1; ++s; }

        auto nbytes = bigint_to_bytes(n).size();
        int bits = static_cast<int>(nbytes * 8);

        for (int r = 0; r < rounds; ++r) {
            BigInt a = random_bigint_bits(bits);
            if (a >= n - 2) {
                a %= (n - 3);
                a += 2;
            } else {
                a += 2;
            }
            if (miller_rabin_witness(a, n, d, s)) return false;
        }
        return true;
    }

    BigInt generate_prime(int bits) {
        while (true) {
            BigInt cand = random_bigint_bits(bits);
            if (is_probable_prime(cand, 32)) return cand;
        }
    }

} // namespace CryptoLib