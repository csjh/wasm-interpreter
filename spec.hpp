#pragma once

#include <cstdint>
#include <vector>

namespace Mitey {
enum class valtype {
    // numtype
    i32 = 0x7f,
    i64 = 0x7e,
    f32 = 0x7d,
    f64 = 0x7c,

    // // vectype
    // v128 = 0x7b,

    // // reftype
    // funcref = 0x70,
    // externref = 0x6f,
};

static inline bool is_valtype(uint8_t byte) {
    return byte == static_cast<uint8_t>(valtype::i32) ||
           byte == static_cast<uint8_t>(valtype::i64) ||
           byte == static_cast<uint8_t>(valtype::f32) ||
           byte == static_cast<uint8_t>(valtype::f64);
}

struct Signature {
    std::vector<valtype> params;
    std::vector<valtype> results;
};

enum class mut {
    const_ = 0x0,
    var = 0x1,
};

static inline bool is_mut(uint8_t byte) {
    return byte == static_cast<uint8_t>(mut::const_) ||
           byte == static_cast<uint8_t>(mut::var);
}

static inline int64_t read_sleb128(uint8_t *&iter) {
    int64_t result = 0;
    uint32_t shift = 0;
    uint8_t byte;
    do {
        byte = *iter++;
        result |= (byte & 0x7f) << shift;
        shift += 7;
    } while (byte & 0x80);
    if (shift < 64 && (byte & 0x40)) {
        result |= -1 << shift;
    }
    return result;
}

template <typename T, uint8_t bits = sizeof(T) * 8>
static inline T safe_read_sleb128(uint8_t *&iter) {
    assert(bits / 8 <= sizeof(T));
    uint64_t result = read_sleb128(iter);
    assert(result <= (1ULL << (bits - 1)) - 1);
    assert(result >= -(1ULL << (bits - 1)));
    return static_cast<T>(result);
}

static inline uint64_t read_leb128(uint8_t *&iter) {
    uint64_t result = 0;
    uint32_t shift = 0;
    uint8_t byte;
    do {
        byte = *iter++;
        result |= (byte & 0x7f) << shift;
        shift += 7;
    } while (byte & 0x80);
    return result;
}

template <typename T>
static inline T safe_read_leb128(uint8_t *&iter, uint8_t bits = sizeof(T) * 8) {
    assert(bits / 8 <= sizeof(T));
    uint64_t result = read_leb128(iter);
    assert(result <= (1ULL << bits) - 1);
    return static_cast<T>(result);
}

// clang-format off
enum class Instruction {
    unreachable = 0x00,
    nop         = 0x01,
    block       = 0x02,
    loop        = 0x03,
    if_         = 0x04,
    else_       = 0x05,

    // insert exception proposal here

    end  = 0x0b,
    br   = 0x0c, br_if         = 0x0d, br_table = 0x0e,
    call = 0x10, call_indirect = 0x11, return_  = 0x0f,

    // insert return call here

    drop   = 0x1a,
    select = 0x1b,

    // insert some rando instructions here

    localget = 0x20, globalget = 0x23,
    localset = 0x21, globalset = 0x24,
    localtee = 0x22,

    // insert table.{get,set} here

    i32load = 0x28, i64load = 0x29,
    f32load = 0x2a, f64load = 0x2b,

    i32load8_s  = 0x2c, i32load8_u  = 0x2d,
    i32load16_s = 0x2e, i32load16_u = 0x2f,
    i64load8_s  = 0x30, i64load8_u  = 0x31,
    i64load16_s = 0x32, i64load16_u = 0x33,
    i64load32_s = 0x34, i64load32_u = 0x35,

    i32store  = 0x36, i64store   = 0x37,
    f32store  = 0x38, f64store   = 0x39,
    i32store8 = 0x3a, i32store16 = 0x3b,
    i64store8 = 0x3c, i64store16 = 0x3d, i64store32 = 0x3e,

    memorysize = 0x3f,
    memorygrow = 0x40,

    i32const = 0x41, i64const = 0x42,
    f32const = 0x43, f64const = 0x44,

    i32eqz  = 0x45, i64eqz  = 0x50,
    i32eq   = 0x46, i64eq   = 0x51,
    i32ne   = 0x47, i64ne   = 0x52,
    i32lt_s = 0x48, i64lt_s = 0x53,
    i32lt_u = 0x49, i64lt_u = 0x54,
    i32gt_s = 0x4a, i64gt_s = 0x55,
    i32gt_u = 0x4b, i64gt_u = 0x56,
    i32le_s = 0x4c, i64le_s = 0x57,
    i32le_u = 0x4d, i64le_u = 0x58,
    i32ge_s = 0x4e, i64ge_s = 0x59,
    i32ge_u = 0x4f, i64ge_u = 0x5a,

    f32eq = 0x5b, f64eq = 0x61,
    f32ne = 0x5c, f64ne = 0x62,
    f32lt = 0x5d, f64lt = 0x63,
    f32gt = 0x5e, f64gt = 0x64,
    f32le = 0x5f, f64le = 0x65,
    f32ge = 0x60, f64ge = 0x66,

    i32clz    = 0x67, i64clz    = 0x79,
    i32ctz    = 0x68, i64ctz    = 0x7a,
    i32popcnt = 0x69, i64popcnt = 0x7b,
    i32add    = 0x6a, i64add    = 0x7c,
    i32sub    = 0x6b, i64sub    = 0x7d,
    i32mul    = 0x6c, i64mul    = 0x7e,
    i32div_s  = 0x6d, i64div_s  = 0x7f,
    i32div_u  = 0x6e, i64div_u  = 0x80,
    i32rem_s  = 0x6f, i64rem_s  = 0x81,
    i32rem_u  = 0x70, i64rem_u  = 0x82,
    i32and    = 0x71, i64and    = 0x83,
    i32or     = 0x72, i64or     = 0x84,
    i32xor    = 0x73, i64xor    = 0x85,
    i32shl    = 0x74, i64shl    = 0x86,
    i32shr_s  = 0x75, i64shr_s  = 0x87,
    i32shr_u  = 0x76, i64shr_u  = 0x88,
    i32rotl   = 0x77, i64rotl   = 0x89,
    i32rotr   = 0x78, i64rotr   = 0x8a,

    f32abs      = 0x8b, f64abs      = 0x99,
    f32neg      = 0x8c, f64neg      = 0x9a,
    f32ceil     = 0x8d, f64ceil     = 0x9b,
    f32floor    = 0x8e, f64floor    = 0x9c,
    f32trunc    = 0x8f, f64trunc    = 0x9d,
    f32nearest  = 0x90, f64nearest  = 0x9e,
    f32sqrt     = 0x91, f64sqrt     = 0x9f,
    f32add      = 0x92, f64add      = 0xa0,
    f32sub      = 0x93, f64sub      = 0xa1,
    f32mul      = 0x94, f64mul      = 0xa2,
    f32div      = 0x95, f64div      = 0xa3,
    f32min      = 0x96, f64min      = 0xa4,
    f32max      = 0x97, f64max      = 0xa5,
    f32copysign = 0x98, f64copysign = 0xa6,

    i32wrap_i64 = 0xa7, i64extend_i32_s = 0xac, i64extend_i32_u = 0xad,

    i32trunc_f32_s = 0xa8, i64trunc_f32_s = 0xae,
    i32trunc_f32_u = 0xa9, i64trunc_f32_u = 0xaf,
    i32trunc_f64_s = 0xaa, i64trunc_f64_s = 0xb0,
    i32trunc_f64_u = 0xab, i64trunc_f64_u = 0xb1,

    f32convert_i32_s = 0xb2, f64convert_i32_s = 0xb7,
    f32convert_i32_u = 0xb3, f64convert_i32_u = 0xb8,
    f32convert_i64_s = 0xb4, f64convert_i64_s = 0xb9,
    f32convert_i64_u = 0xb5, f64convert_i64_u = 0xba,

    f32demote_f64 = 0xb6, f64promote_f32 = 0xbb,

    i32reinterpret_f32 = 0xbc, f32reinterpret_i32 = 0xbe,
    i64reinterpret_f64 = 0xbd, f64reinterpret_i64 = 0xbf,

    // insert sign extension proposal here
};
// clang-format on

static inline bool is_instruction(uint8_t byte) {
    // todo: figure out best way for this
    return true;
}
} // namespace Mitey