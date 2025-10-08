#include "oaep.hpp"
#include "hash_utils.hpp"
#include "random_utils.hpp"
#include <stdexcept>
#include <algorithm>

namespace CryptoLib {

    static std::vector<std::uint8_t> i2osp(std::uint32_t x, std::size_t len) {
        std::vector<std::uint8_t> out(len, 0);
        for (std::size_t i = 0; i < len; ++i) {
            out[len - 1 - i] = static_cast<std::uint8_t>((x >> (8 * i)) & 0xFF);
        }
        return out;
    }

    std::vector<std::uint8_t> mgf1_sha256(const std::vector<std::uint8_t>& seed, std::size_t len) {
        std::vector<std::uint8_t> out;
        out.reserve(len);
        std::uint32_t counter = 0;
        const std::size_t hLen = 32;

        while (out.size() < len) {
            auto C = i2osp(counter, 4);
            std::vector<std::uint8_t> input;
            input.reserve(seed.size() + 4);
            input.insert(input.end(), seed.begin(), seed.end());
            input.insert(input.end(), C.begin(), C.end());

            auto h = sha256(input);
            std::size_t take = std::min(hLen, len - out.size());
            out.insert(out.end(), h.begin(), h.begin() + take);
            counter++;
        }
        return out;
    }

    std::vector<std::uint8_t> oaep_encode(const std::vector<std::uint8_t>& msg, std::size_t k) {
        const std::size_t hLen = 32; // SHA-256
        if (k < 2 * hLen + 2) throw std::invalid_argument("oaep_encode: modulus too small");
        if (msg.size() > k - 2 * hLen - 2) throw std::invalid_argument("oaep_encode: message too long");

        std::vector<std::uint8_t> lHash = sha256({});
        std::size_t psLen = k - msg.size() - 2 * hLen - 2;

        // DB = lHash || PS (zero bytes) || 0x01 || M
        std::vector<std::uint8_t> DB;
        DB.reserve(hLen + psLen + 1 + msg.size());
        DB.insert(DB.end(), lHash.begin(), lHash.end());
        DB.insert(DB.end(), psLen, 0x00);
        DB.push_back(0x01);
        DB.insert(DB.end(), msg.begin(), msg.end());

        // seed: hLen random bytes
        std::vector<std::uint8_t> seed(hLen);
        csprng_bytes(seed);

        // dbMask = MGF1(seed, k - hLen - 1)
        auto dbMask = mgf1_sha256(seed, k - hLen - 1);
        // maskedDB = DB XOR dbMask
        std::vector<std::uint8_t> maskedDB(DB.size());
        for (std::size_t i = 0; i < DB.size(); ++i) maskedDB[i] = DB[i] ^ dbMask[i];

        // seedMask = MGF1(maskedDB, hLen)
        auto seedMask = mgf1_sha256(maskedDB, hLen);
        // maskedSeed = seed XOR seedMask
        std::vector<std::uint8_t> maskedSeed(hLen);
        for (std::size_t i = 0; i < hLen; ++i) maskedSeed[i] = seed[i] ^ seedMask[i];

        // EM = 0x00 || maskedSeed || maskedDB
        std::vector<std::uint8_t> EM;
        EM.reserve(1 + hLen + maskedDB.size());
        EM.push_back(0x00);
        EM.insert(EM.end(), maskedSeed.begin(), maskedSeed.end());
        EM.insert(EM.end(), maskedDB.begin(), maskedDB.end());

        if (EM.size() != k) throw std::runtime_error("oaep_encode: output size mismatch");
        return EM;
    }

    std::vector<std::uint8_t> oaep_decode(const std::vector<std::uint8_t>& em, std::size_t k) {
        const std::size_t hLen = 32; // SHA-256
        if (k < 2 * hLen + 2) throw std::invalid_argument("oaep_decode: modulus too small");
        if (em.size() != k) throw std::invalid_argument("oaep_decode: input size mismatch");

        if (em[0] != 0x00) throw std::runtime_error("oaep_decode: leading 0x00 missing");

        // Split EM
        std::vector<std::uint8_t> maskedSeed(em.begin() + 1, em.begin() + 1 + hLen);
        std::vector<std::uint8_t> maskedDB(em.begin() + 1 + hLen, em.end());

        // seedMask = MGF1(maskedDB, hLen)
        auto seedMask = mgf1_sha256(maskedDB, hLen);
        // seed = maskedSeed XOR seedMask
        std::vector<std::uint8_t> seed(hLen);
        for (std::size_t i = 0; i < hLen; ++i) seed[i] = maskedSeed[i] ^ seedMask[i];

        // dbMask = MGF1(seed, k - hLen - 1)
        auto dbMask = mgf1_sha256(seed, k - hLen - 1);
        // DB = maskedDB XOR dbMask
        std::vector<std::uint8_t> DB(maskedDB.size());
        for (std::size_t i = 0; i < maskedDB.size(); ++i) DB[i] = maskedDB[i] ^ dbMask[i];

        // DB = lHash || PS || 0x01 || M
        auto lHash = sha256({});
        // verifikuj lHash
        if (!std::equal(DB.begin(), DB.begin() + hLen, lHash.begin(), lHash.end()))
            throw std::runtime_error("oaep_decode: lHash mismatch");

        // pronađi 0x01 posle PS (nula bajtova)
        std::size_t idx = hLen;
        while (idx < DB.size() && DB[idx] == 0x00) idx++;
        if (idx >= DB.size() || DB[idx] != 0x01) throw std::runtime_error("oaep_decode: 0x01 separator missing");
        idx++; // skip 0x01

        // preostalo je M
        std::vector<std::uint8_t> M(DB.begin() + idx, DB.end());
        return M;
    }

} // namespace CryptoLib