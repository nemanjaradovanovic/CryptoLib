#pragma once
#include <vector>
#include <cstdint>

namespace CryptoLib {
    // SHA-256 hash, vraća 32 bajta
    std::vector<std::uint8_t> sha256(const std::vector<std::uint8_t>& data);
}