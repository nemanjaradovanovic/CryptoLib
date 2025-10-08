#include "hash_utils.hpp"
#include <stdexcept>
#include <windows.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

namespace CryptoLib {
    std::vector<std::uint8_t> sha256(const std::vector<std::uint8_t>& data) {
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
        if (status != 0) throw std::runtime_error("BCryptOpenAlgorithmProvider SHA-256 failed");

        DWORD hashObjectSize = 0, dataLen = 0;
        status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&hashObjectSize, sizeof(hashObjectSize), &dataLen, 0);
        if (status != 0) { BCryptCloseAlgorithmProvider(hAlg,0); throw std::runtime_error("BCryptGetProperty OBJECT_LENGTH failed"); }

        std::vector<std::uint8_t> hashObject(hashObjectSize);

        DWORD hashLen = 0;
        status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&hashLen, sizeof(hashLen), &dataLen, 0);
        if (status != 0 || hashLen != 32) { BCryptCloseAlgorithmProvider(hAlg,0); throw std::runtime_error("BCryptGetProperty HASH_LENGTH failed"); }

        BCRYPT_HASH_HANDLE hHash = nullptr;
        status = BCryptCreateHash(hAlg, &hHash, hashObject.data(), static_cast<ULONG>(hashObject.size()), nullptr, 0, 0);
        if (status != 0) { BCryptCloseAlgorithmProvider(hAlg,0); throw std::runtime_error("BCryptCreateHash failed"); }

        status = BCryptHashData(hHash, const_cast<PUCHAR>(data.data()), static_cast<ULONG>(data.size()), 0);
        if (status != 0) { BCryptDestroyHash(hHash); BCryptCloseAlgorithmProvider(hAlg,0); throw std::runtime_error("BCryptHashData failed"); }

        std::vector<std::uint8_t> hash(hashLen);
        status = BCryptFinishHash(hHash, hash.data(), hashLen, 0);
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);

        if (status != 0) throw std::runtime_error("BCryptFinishHash failed");
        return hash;
    }
}