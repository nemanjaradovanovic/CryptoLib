#include "bigint_utils.hpp"
#include <stdexcept>

namespace CryptoLib {

    BigInt modexp(const BigInt& base, const BigInt& exp, const BigInt& mod) {
        if (mod == 0) throw std::invalid_argument("modexp: mod must be > 0");
        BigInt result = 1;
        BigInt b = base % mod;
        BigInt e = exp;
        while (e > 0) {
            if ((e & 1) != 0) {
                result = (result * b) % mod;
            }
            b = (b * b) % mod;
            e >>= 1;
        }
        return result;
    }

    BigInt egcd(const BigInt& a, const BigInt& b, BigInt& x, BigInt& y) {
        if (b == 0) {
            x = 1;
            y = 0;
            return a;
        }
        BigInt x1, y1;
        BigInt g = egcd(b, a % b, x1, y1);
        x = y1;
        y = x1 - (a / b) * y1;
        return g;
    }

    BigInt modinv(const BigInt& a, const BigInt& m) {
        BigInt x, y;
        BigInt g = egcd(a, m, x, y);
        if (g != 1) {
            throw std::runtime_error("modinv: inverse does not exist");
        }
        BigInt inv = x % m;
        if (inv < 0) inv += m;
        return inv;
    }

    std::vector<std::uint8_t> bigint_to_bytes(const BigInt& x) {
        if (x < 0) throw std::invalid_argument("bigint_to_bytes: negative not supported");
        BigInt v = x;
        std::vector<std::uint8_t> out;
        while (v > 0) {
            std::uint8_t byte = static_cast<std::uint8_t>( (v & 0xFF).convert_to<unsigned long long>() );
            out.push_back(byte);
            v >>= 8;
        }
        // little-endian collected -> reverse to big-endian
        std::reverse(out.begin(), out.end());
        if (out.empty()) out.push_back(0); // represent zero
        return out;
    }

    BigInt bytes_to_bigint(const std::vector<std::uint8_t>& bytes) {
        BigInt x = 0;
        for (std::uint8_t b : bytes) {
            x <<= 8;
            x += b;
        }
        return x;
    }

} // namespace CryptoLib