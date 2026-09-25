// Certificates: what a wallet, or a manager whose own certificate is chained before it, signs to
// admit a key under an account, and what revokes it. Text, so that a wallet shows it as it is
// and the Solana CLI can sign it (`solana sign-offchain-message`).
//
//   converge-member-v1
//   account: <wallet address, base58>
//   member: <member key, base58>
//   alias: <alias>
//   scope: member | manager
//   expires: <unix seconds, 0 = until revoked>
//
//   converge-revoke-v1
//   account: <wallet address, base58>
//   member: <member key, base58>
//   issued: <unix seconds>
//
// The signature is over the body bytes as a wallet's signMessage signs them, or over Solana's
// off-chain message wrapper of them (`\xffsolana offchain` + version 0 + format + u16 length +
// body), as the CLI signs. A verifier accepts either; nothing else.
#pragma once

#include "handshake.hpp"

#include <charconv>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>

namespace converge::link {

struct member_certificate {
    key32 account{}, member{};
    std::string alias;
    scope granted = scope::member;
    std::int64_t expires = 0;
    std::string body() const {
        return "converge-member-v1\naccount: " + identity_text(account) + "\nmember: " + identity_text(member) + "\nalias: " + alias +
               "\nscope: " + (granted == scope::manager ? "manager" : "member") + "\nexpires: " + std::to_string(expires);
    }
};
struct revocation {
    key32 account{}, member{};
    std::int64_t issued = 0;
    std::string body() const {
        return "converge-revoke-v1\naccount: " + identity_text(account) + "\nmember: " + identity_text(member) + "\nissued: " + std::to_string(issued);
    }
};

namespace detail {
inline std::optional<std::map<std::string, std::string>> fields(std::string_view body, std::string_view head, std::size_t count) {
    std::map<std::string, std::string> out;
    std::size_t pos = 0;
    std::string_view first = body.substr(0, body.find('\n'));
    if (first != head) return std::nullopt;
    pos = first.size() + 1;
    while (pos <= body.size()) {
        const auto nl = body.find('\n', pos);
        const auto line = body.substr(pos, nl == std::string_view::npos ? std::string_view::npos : nl - pos);
        const auto colon = line.find(": ");
        if (colon == std::string_view::npos) return std::nullopt;
        out.emplace(std::string(line.substr(0, colon)), std::string(line.substr(colon + 2)));
        if (nl == std::string_view::npos) break;
        pos = nl + 1;
    }
    if (out.size() != count) return std::nullopt;
    return out;
}
inline std::optional<std::int64_t> number(const std::string& s) {
    std::int64_t v = 0;
    auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
    if (ec != std::errc() || p != s.data() + s.size()) return std::nullopt;
    return v;
}
} // namespace detail

inline std::optional<member_certificate> parse_member_certificate(std::string_view body) {
    auto f = detail::fields(body, "converge-member-v1", 5);
    if (!f) return std::nullopt;
    member_certificate c;
    auto a = identity_from_text(f->at("account")), m = identity_from_text(f->at("member"));
    auto e = detail::number(f->at("expires"));
    if (!a || !m || !e || !f->contains("alias") || !f->contains("scope")) return std::nullopt;
    if (f->at("scope") == "member") c.granted = scope::member;
    else if (f->at("scope") == "manager") c.granted = scope::manager;
    else return std::nullopt;
    c.account = *a; c.member = *m; c.alias = f->at("alias"); c.expires = *e;
    if (c.alias.empty() || c.alias.size() > limits::label) return std::nullopt;
    return c;
}
inline std::optional<revocation> parse_revocation(std::string_view body) {
    auto f = detail::fields(body, "converge-revoke-v1", 3);
    if (!f) return std::nullopt;
    revocation r;
    auto a = identity_from_text(f->at("account")), m = identity_from_text(f->at("member"));
    auto i = detail::number(f->at("issued"));
    if (!a || !m || !i) return std::nullopt;
    r.account = *a; r.member = *m; r.issued = *i;
    return r;
}

// Solana's off-chain message wrapper, version 0, format 0 (restricted ASCII) or 1 (UTF-8).
inline bytes offchain_wrapper(std::string_view body) {
    bytes out{0xff, 's', 'o', 'l', 'a', 'n', 'a', ' ', 'o', 'f', 'f', 'c', 'h', 'a', 'i', 'n', 0};
    bool ascii = true;
    for (unsigned char c : body) if (c < 0x20 || c > 0x7e) { if (c != '\n') ascii = false; }
    out.push_back(ascii ? 0 : 1);
    out.push_back(static_cast<std::uint8_t>(body.size() & 0xff));
    out.push_back(static_cast<std::uint8_t>(body.size() >> 8));
    out.insert(out.end(), body.begin(), body.end());
    return out;
}

// True when `signer` signed `body`, plainly or through the off-chain wrapper.
inline bool verify_certificate_signature(const certificate& c) {
    if (crypto::ed25519_verify(c.signer, c.body, c.signature)) return true;
    const auto wrapped = offchain_wrapper(c.body);
    return crypto::ed25519_verify(c.signer, std::span<const std::uint8_t>(wrapped), c.signature);
}

// The relay's check of a certificate chain for `member` at `now`: the first certificate is signed by
// the account's wallet, each following one by the member the previous admitted with manager scope,
// and the last names `member`. Returns the scope granted, or nothing.
inline std::optional<std::pair<key32, member_certificate>> verify_chain(const std::vector<certificate>& chain, const key32& member, std::int64_t now) {
    if (chain.empty() || chain.size() > limits::certificates) return std::nullopt;
    std::optional<key32> account;
    std::optional<key32> expected_signer;
    member_certificate last;
    for (const auto& c : chain) {
        auto mc = parse_member_certificate(c.body);
        if (!mc || !verify_certificate_signature(c)) return std::nullopt;
        if (mc->expires != 0 && mc->expires < now) return std::nullopt;
        if (!account) { account = mc->account; if (c.signer != mc->account) return std::nullopt; }   // the root is the wallet itself
        else {
            if (mc->account != *account) return std::nullopt;
            if (!expected_signer || c.signer != *expected_signer) return std::nullopt;               // signed by the manager before it
        }
        expected_signer = mc->granted == scope::manager ? std::optional<key32>(mc->member) : std::nullopt;
        last = *mc;
    }
    if (last.member != member) return std::nullopt;
    return std::make_pair(*account, last);
}

} // namespace converge::link
