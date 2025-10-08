#pragma once
#include <vector>
#include <cstdint>
#include <string>

namespace CryptoLib {

    // MGF1 sa SHA-256
    std::vector<std::uint8_t> mgf1_sha256(const std::vector<std::uint8_t>& seed, std::size_t len);

    // OAEP encode/decode sa SHA-256 i prazan label (""), po RFC 3447
    // k = dužina modula u bajtovima
    std::vector<std::uint8_t> oaep_encode(const std::vector<std::uint8_t>& msg, std::size_t k);
    std::vector<std::uint8_t> oaep_decode(const std::vector<std::uint8_t>& em, std::size_t k);

} // namespace CryptoLib