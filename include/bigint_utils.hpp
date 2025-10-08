#pragma once
#include <vector>
#include <cstdint>
#include <boost/multiprecision/cpp_int.hpp>

namespace CryptoLib {

    using BigInt = boost::multiprecision::cpp_int;

    BigInt modexp(const BigInt& base, const BigInt& exp, const BigInt& mod);
    BigInt egcd(const BigInt& a, const BigInt& b, BigInt& x, BigInt& y);
    BigInt modinv(const BigInt& a, const BigInt& m);

    std::vector<std::uint8_t> bigint_to_bytes(const BigInt& x);
    BigInt bytes_to_bigint(const std::vector<std::uint8_t>& bytes);

} // namespace CryptoLib