#pragma once
#include <boost/multiprecision/cpp_int.hpp>
#include <cstdint>

namespace CryptoLib {
    using BigInt = boost::multiprecision::cpp_int;

    // Generiše slučajan veliki broj sa zadatim brojem bitova
    BigInt random_bigint_bits(int bits);

    // Miller–Rabin test za proveru da li je broj verovatno prost
    bool is_probable_prime(const BigInt& n, int rounds = 32);

    // Generiše prost broj zadate dužine u bitovima
    BigInt generate_prime(int bits);
}