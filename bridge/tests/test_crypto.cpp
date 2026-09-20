#include "crypto.hpp"
#include <cstdio>
#include <string>

using namespace converge::crypto;
static int failures = 0;
#define CHECK(x) do { if (!(x)) { std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); ++failures; } } while (0)

int main() {
    CHECK(b64_encode(reinterpret_cast<const std::uint8_t*>("hi!"), 3) == "aGkh");
    CHECK(b64_encode(reinterpret_cast<const std::uint8_t*>("hi"), 2) == "aGk=");
    auto d = b64_decode("aGkh"); CHECK(d && std::string(d->begin(), d->end()) == "hi!");
    CHECK(hex(sha256("abc").data(), 32) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    Identity a, b;
    auto sa = a.shared_secret(b.pub()), sb = b.shared_secret(a.pub());
    CHECK(sa == sb);
    CHECK(sas(a.pub(), b.pub()) == sas(b.pub(), a.pub()));
    CHECK(sas(a.pub(), b.pub()).size() == 6);

    Sealer sealer_a(derive_session(sa, a.pub(), b.pub(), "call_one"), a.pub(), b.pub());
    Sealer sealer_b(derive_session(sb, b.pub(), a.pub(), "call_one"), b.pub(), a.pub());
    auto f1 = sealer_a.seal("first"), f2 = sealer_a.seal("second");
    CHECK(sealer_b.open(f1.data(), f1.size()).value_or("") == "first");
    CHECK(!sealer_b.open(f1.data(), f1.size()));                       // replay rejected
    CHECK(sealer_b.open(f2.data(), f2.size()).value_or("") == "second");
    CHECK(!sealer_a.open(f2.data(), f2.size()));                       // own direction rejected
    f2[20] ^= 1;
    CHECK(!sealer_b.open(f2.data(), f2.size()));                       // tamper rejected
    auto back = sealer_b.seal("reply");
    CHECK(sealer_a.open(back.data(), back.size()).value_or("") == "reply");

    // A third party's keys never open the channel, even with the same peer pubkey.
    Identity c;
    auto sc = c.shared_secret(a.pub());
    Sealer sealer_c(derive_session(sc, c.pub(), a.pub(), "call_one"), c.pub(), a.pub());
    auto f3 = sealer_a.seal("x");
    CHECK(!sealer_c.open(f3.data(), f3.size()));
    // Key derivation is symmetric: both sides agree regardless of who called whom.
    CHECK(derive_session(sa, a.pub(), b.pub(), "call_one").send == derive_session(sb, b.pub(), a.pub(), "call_one").recv);
    CHECK(derive_session(sa, a.pub(), b.pub(), "call_one").recv == derive_session(sb, b.pub(), a.pub(), "call_one").send);

    // A second call between the same live processes has fresh keys despite reset counters.
    const auto next_a = derive_session(sa, a.pub(), b.pub(), "call_two");
    const auto next_b = derive_session(sb, b.pub(), a.pub(), "call_two");
    CHECK(next_a.send == next_b.recv);
    CHECK(next_a.send != derive_session(sa, a.pub(), b.pub(), "call_one").send);
    Sealer a2(next_a, a.pub(), b.pub()), b2(next_b, b.pub(), a.pub());
    CHECK(!b2.open(f1.data(), f1.size()));
    auto fresh = a2.seal("first");
    CHECK(fresh != f1);
    CHECK(b2.open(fresh.data(), fresh.size()).value_or("") == "first");
    bool rejected_empty = false;
    try { derive_session(sa, a.pub(), b.pub(), ""); }
    catch (...) { rejected_empty = true; }
    CHECK(rejected_empty);

    if (failures) { std::printf("%d failure(s)\n", failures); return 1; }
    std::puts("all crypto tests passed");
    return 0;
}
