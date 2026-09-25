// QSF, the binary frame format of mm-studios/a0 (base/kernel/include/a0/qsf), adapted for
// an untrusted network boundary. This copy is the protocol's: the relay and the web application
// take it from the client release, so that one definition serves every end of the link. The wire format is a0's, unchanged:
//
//   frame  = header(16) | body
//   header = u16 magic 0x5153 ('QS') | u16 version | u32 code | u64 body_size     (little endian)
//   body   = positional fields, no tags: arithmetic values little endian; a string or byte
//            sequence is a u64 count followed by that many raw bytes.
//
// What differs from a0: the reader validates the header and every length against an explicit
// cap before allocating (a0's containers have no cap because they read trusted local files),
// and the writer grows a vector rather than using a0's per-code capacity cache. Token
// quantities are always u64 base units; there is no floating point on the wire.
#pragma once

#include <bit>
#include <cstdint>
#include <cstring>
#include <span>
#include <expected>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace converge::qsf {

using blob = std::vector<std::uint8_t>;

enum class error : std::uint8_t {
    truncated,        // fewer bytes than the header or a field needs
    bad_magic,
    bad_version,      // frame version 0, or newer than this build understands
    bad_size,         // body_size disagrees with the bytes present, or exceeds max_frame
    wrong_code,       // a valid frame, but not the message the caller expected
    too_long,         // a string/bytes count above its cap
    bad_value,        // an enum or flag outside its defined range
    trailing_bytes,   // body longer than the message definition
};
template <class T> using result = std::expected<T, error>;
using status = std::expected<void, error>;

inline constexpr std::uint16_t frame_magic = 0x5153;   // 'QS'
inline constexpr std::size_t header_size = 16;
inline constexpr std::size_t max_frame = 256 * 1024 + 4096;   // one sealed peer payload (256 KiB) with headers

template <class T> concept wire_arithmetic = std::is_integral_v<T> && !std::is_same_v<T, bool>;

template <wire_arithmetic T> constexpr T to_le(T v) noexcept {
    if constexpr (std::endian::native == std::endian::little || sizeof(T) == 1) return v;
    else return std::byteswap(v);
}

class writer {
public:
    writer(std::uint32_t code, std::uint16_t version) : buf_(header_size) {
        put_at(0, frame_magic); put_at(2, version); put_at(4, code);
    }
    template <wire_arithmetic T> writer& put(T v) {
        v = to_le(v);
        const auto* p = reinterpret_cast<const std::uint8_t*>(&v);
        buf_.insert(buf_.end(), p, p + sizeof(T));
        return *this;
    }
    writer& put_bool(bool v) { return put<std::uint8_t>(v ? 1 : 0); }
    writer& put_bytes(const std::uint8_t* data, std::size_t n) {
        put<std::uint64_t>(n);
        buf_.insert(buf_.end(), data, data + n);
        return *this;
    }
    writer& put_string(std::string_view s) {
        return put_bytes(reinterpret_cast<const std::uint8_t*>(s.data()), s.size());
    }
    [[nodiscard]] blob finish() {
        put_at<std::uint64_t>(8, buf_.size() - header_size);
        return std::move(buf_);
    }
private:
    template <wire_arithmetic T> void put_at(std::size_t at, T v) {
        v = to_le(v);
        std::memcpy(buf_.data() + at, &v, sizeof(T));
    }
    blob buf_;
};

struct frame_info { std::uint16_t version = 0; std::uint32_t code = 0; };

// Validates the header only. Used by dispatchers to route a frame before decoding it.
inline result<frame_info> peek(std::span<const std::uint8_t> frame) {
    if (frame.size() < header_size) return std::unexpected(error::truncated);
    auto rd = [&](std::size_t at, auto& out) { std::memcpy(&out, frame.data() + at, sizeof(out)); out = to_le(out); };
    std::uint16_t magic = 0, version = 0; std::uint32_t code = 0; std::uint64_t body = 0;
    rd(0, magic); rd(2, version); rd(4, code); rd(8, body);
    if (magic != frame_magic) return std::unexpected(error::bad_magic);
    if (version == 0) return std::unexpected(error::bad_version);
    if (frame.size() > max_frame || body != frame.size() - header_size) return std::unexpected(error::bad_size);
    return frame_info{version, code};
}

class reader {
public:
    // `max_version`: the newest schema this build can read for `code`.
    static result<reader> open(std::span<const std::uint8_t> frame, std::uint32_t code, std::uint16_t max_version) {
        auto info = peek(frame);
        if (!info) return std::unexpected(info.error());
        if (info->code != code) return std::unexpected(error::wrong_code);
        if (info->version > max_version) return std::unexpected(error::bad_version);
        return reader{frame.subspan(header_size), info->version};
    }
    [[nodiscard]] std::uint16_t version() const noexcept { return version_; }
    template <wire_arithmetic T> result<T> get() {
        if (body_.size() - pos_ < sizeof(T)) return std::unexpected(error::truncated);
        T v; std::memcpy(&v, body_.data() + pos_, sizeof(T)); pos_ += sizeof(T);
        return to_le(v);
    }
    result<bool> get_bool() {
        auto v = get<std::uint8_t>();
        if (!v) return std::unexpected(v.error());
        if (*v > 1) return std::unexpected(error::bad_value);
        return *v == 1;
    }
    result<blob> get_bytes(std::size_t max_len) {
        auto n = get<std::uint64_t>();
        if (!n) return std::unexpected(n.error());
        if (*n > max_len) return std::unexpected(error::too_long);
        if (body_.size() - pos_ < *n) return std::unexpected(error::truncated);
        blob out(body_.begin() + static_cast<std::ptrdiff_t>(pos_), body_.begin() + static_cast<std::ptrdiff_t>(pos_ + *n));
        pos_ += *n;
        return out;
    }
    result<std::string> get_string(std::size_t max_len) {
        auto b = get_bytes(max_len);
        if (!b) return std::unexpected(b.error());
        return std::string(b->begin(), b->end());
    }
    // Every message ends here: a body longer than its definition is malformed.
    status done() const {
        if (pos_ != body_.size()) return std::unexpected(error::trailing_bytes);
        return {};
    }
private:
    reader(std::span<const std::uint8_t> body, std::uint16_t version) : body_(body), version_(version) {}
    std::span<const std::uint8_t> body_;
    std::size_t pos_ = 0;
    std::uint16_t version_ = 0;
};

} // namespace converge::qsf
