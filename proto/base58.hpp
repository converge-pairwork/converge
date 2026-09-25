// Base58 (the Bitcoin alphabet, which Solana addresses use). Adapted from airpump (wgraph/codec.hpp).
// A Solana address is the base58 of an Ed25519 public key, and in this protocol an identity is
// that same encoding, so the two are one thing.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace converge::base58 {
inline std::string encode(const std::uint8_t* data, std::size_t len) {
    static constexpr char alphabet[] =
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    std::size_t zeros = 0;
    while (zeros < len && data[zeros] == 0) ++zeros;
    // Big-number base conversion; digits accumulate little-endian.
    std::vector<std::uint8_t> digits;
    digits.reserve(len * 138 / 100 + 1);
    for (std::size_t i = zeros; i < len; ++i) {
        unsigned carry = data[i];
        for (std::uint8_t& d : digits) {
            carry += static_cast<unsigned>(d) << 8;
            d = static_cast<std::uint8_t>(carry % 58);
            carry /= 58;
        }
        while (carry) {
            digits.push_back(static_cast<std::uint8_t>(carry % 58));
            carry /= 58;
        }
    }
    std::string out(zeros, '1');
    for (auto it = digits.rbegin(); it != digits.rend(); ++it)
        out += alphabet[*it];
    return out;
}

// Inverse of encode; empty result for an invalid character.
inline std::vector<std::uint8_t> decode(std::string_view s) {
    static constexpr char alphabet[] =
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    std::size_t zeros = 0;
    while (zeros < s.size() && s[zeros] == '1') ++zeros;
    std::vector<std::uint8_t> bytes; // little-endian accumulator
    bytes.reserve(s.size() * 733 / 1000 + 1);
    for (std::size_t i = zeros; i < s.size(); ++i) {
        const char* pos = std::char_traits<char>::find(alphabet, 58, s[i]);
        if (!pos) return {};
        unsigned carry = static_cast<unsigned>(pos - alphabet);
        for (std::uint8_t& b : bytes) {
            carry += static_cast<unsigned>(b) * 58;
            b = static_cast<std::uint8_t>(carry & 0xff);
            carry >>= 8;
        }
        while (carry) {
            bytes.push_back(static_cast<std::uint8_t>(carry & 0xff));
            carry >>= 8;
        }
    }
    std::vector<std::uint8_t> out(zeros, 0);
    out.insert(out.end(), bytes.rbegin(), bytes.rend());
    return out;
}

} // namespace converge::base58
