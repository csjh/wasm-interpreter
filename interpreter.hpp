#pragma once

#include "spec.hpp"
#include <cassert>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <unordered_map>
#include <vector>

namespace mitey {
[[noreturn]] static inline void trap(std::string message) {
    throw trap_error(message);
}

struct Funcref {
    uint32_t typeidx;
    bool nonnull : 1;
    uint32_t funcidx : 31;
};

using Externref = void *;

// technically unsigned versions don't exist but easier to use if they're here
union WasmValue {
    int32_t i32;
    uint32_t u32;
    int64_t i64;
    uint64_t u64;
    float f32;
    double f64;
    Funcref funcref;
    Externref externref;

    WasmValue(int32_t i32) : i32(i32) {}
    WasmValue(uint32_t u32) : u32(u32) {}
    WasmValue(int64_t i64) : i64(i64) {}
    WasmValue(uint64_t u64) : u64(u64) {}
    WasmValue(float f32) : f32(f32) {}
    WasmValue(double f64) : f64(f64) {}
    WasmValue(Funcref funcref) : funcref(funcref) {}
    WasmValue(Externref externref) : externref(externref) {}

    operator int32_t() { return i32; }
    operator uint32_t() { return u32; }
    operator int64_t() { return i64; }
    operator uint64_t() { return u64; }
    operator float() { return f32; }
    operator double() { return f64; }
    operator Funcref() { return funcref; }
    operator Externref() { return externref; }
};

class WasmMemory {
    uint8_t *memory;
    uint32_t current;
    uint32_t maximum;

    static const uint32_t MAX_PAGES = 65536;

  public:
    static const uint32_t PAGE_SIZE = 65536;

    WasmMemory();
    WasmMemory(uint32_t initial, uint32_t maximum);

    WasmMemory(const WasmMemory &) = delete;
    WasmMemory &operator=(const WasmMemory &) = delete;
    WasmMemory(WasmMemory &&) = delete;
    WasmMemory &operator=(WasmMemory &&) = delete;

    ~WasmMemory();

    uint32_t size() { return current; }
    uint32_t max() { return maximum; }
    uint32_t grow(uint32_t delta);

    template <typename T>
    T load(uint32_t ptr, uint32_t offset, uint32_t /* align */) {
        uint8_t *effective = memory + ptr + offset;
        if (effective + sizeof(T) > memory + current * PAGE_SIZE) {
            trap("out of bounds memory access");
        }
        T value;
        std::memcpy(&value, effective, sizeof(T));
        return value;
    }

    template <typename T>
    void store(uint32_t ptr, uint32_t offset, uint32_t /* align */, T value) {
        uint8_t *effective = memory + ptr + offset;
        if (effective + sizeof(T) > memory + current * PAGE_SIZE) {
            trap("out of bounds memory access");
        }
        std::memcpy(effective, &value, sizeof(T));
    }

    void copy_into(uint32_t ptr, const uint8_t *data, uint32_t length);
    void memcpy(uint32_t dst, uint32_t src, uint32_t length);
    void memset(uint32_t dst, uint8_t value, uint32_t length);
};

class WasmTable {
    WasmValue *elements;
    uint32_t current;
    uint32_t maximum;

  public:
    valtype type;

    WasmTable(valtype type, uint32_t initial, uint32_t maximum);

    WasmTable(const WasmTable &) = delete;
    WasmTable &operator=(const WasmTable &) = delete;
    WasmTable(WasmTable &&table);
    WasmTable &operator=(WasmTable &&) = delete;

    ~WasmTable();

    uint32_t size() { return current; }
    uint32_t max() { return maximum; }
    uint32_t grow(uint32_t delta, WasmValue value);
    WasmValue get(uint32_t idx);
    void set(uint32_t idx, WasmValue value);

    void copy_into(uint32_t ptr, const WasmValue *data, uint32_t length);
    void memcpy(uint32_t dst, uint32_t src, uint32_t length);
    void memset(uint32_t dst, WasmValue value, uint32_t length);
};

struct WasmGlobal {
    valtype type;
    mut _mut;
    WasmValue value;
};

struct FunctionInfo {
    uint8_t *start;
    Signature type;
    std::vector<valtype> locals;
};

struct BrTarget {
    WasmValue *stack;
    uint8_t *dest;
    uint32_t arity;
};

struct StackFrame {
    // locals (points to somewhere in the stack allocation)
    WasmValue *locals;
    // control stack (pointers to the place a br jumps to)
    std::vector<BrTarget> control_stack;
};

struct IfJump {
    uint8_t *else_;
    uint8_t *end;
};

enum class ImportDesc {
    func,
    table,
    mem,
    global,
};

enum class ExportDesc {
    func,
    table,
    mem,
    global,
};

struct Export {
    ExportDesc desc;
    uint32_t idx;
};

struct Segment {
    uint32_t memidx;
    std::vector<uint8_t> data;
};

class safe_byte_iterator {
    uint8_t *iter;
    uint8_t *end;

  public:
    safe_byte_iterator(uint8_t *begin, uint8_t *end);

    uint8_t operator*() const;
    uint8_t operator[](size_t n) const;
    safe_byte_iterator &operator++();
    safe_byte_iterator operator++(int);
    safe_byte_iterator operator+(size_t n) const;
    safe_byte_iterator &operator+=(size_t n);
    ptrdiff_t operator-(safe_byte_iterator other) const;
    ptrdiff_t operator-(const uint8_t *other) const;
    bool operator<(safe_byte_iterator other) const;
    uint8_t *get_with_at_least(size_t n) const;
    bool empty() const;
    bool has_n_left(size_t n) const;

    uint8_t *unsafe_ptr() const { return iter; }
};

using ExportValue =
    std::variant<FunctionInfo, std::shared_ptr<WasmTable>,
                 std::shared_ptr<WasmMemory>, std::shared_ptr<WasmGlobal>>;
using Exports = std::unordered_map<std::string, ExportValue>;
using ModuleImports = std::unordered_map<std::string, ExportValue>;
using Imports = std::unordered_map<std::string, ModuleImports>;

template <size_t N> struct string_literal {
    constexpr string_literal(const char (&str)[N]) {
        std::copy_n(str, N, value);
    }
    char value[N];
    static constexpr size_t size = N - 1;
};

template <size_t N> string_literal(const char (&)[N]) -> string_literal<N>;

class Instance {
    friend class Validator;

    static constexpr uint32_t MAX_LOCALS = 50000;

    Instance(const Instance &) = delete;
    Instance &operator=(const Instance &) = delete;
    Instance(Instance &&) = delete;
    Instance &operator=(Instance &&) = delete;

    // source bytes
    std::unique_ptr<uint8_t, void (*)(uint8_t *)> bytes;
    // WebAssembly.Memory
    std::shared_ptr<WasmMemory> memory;
    // internal stack
    WasmValue *stack;
    // function-specific frames
    std::vector<StackFrame> frames;
    // function info
    std::vector<FunctionInfo> functions;
    // locations of if else/end instructions
    std::unordered_map<uint8_t *, IfJump> if_jumps;
    // locations of block end instructions
    std::unordered_map<uint8_t *, uint8_t *> block_ends;
    // value of globals
    std::vector<std::shared_ptr<WasmGlobal>> globals;
    // maps element indices to the element initializers
    std::vector<std::vector<WasmValue>> elements;
    // types from type section
    std::vector<Signature> types;
    // exports from export section
    Exports exports;
    // stack start for debugging and emptyness assertions
    WasmValue *stack_start;
    // data segments
    std::vector<Segment> data_segments;
    // tables
    std::vector<std::shared_ptr<WasmTable>> tables;

    template <typename Iter> Signature read_blocktype(Iter &iter) {
        uint8_t byte = *iter;
        if (byte == static_cast<uint8_t>(valtype::empty)) {
            ++iter;
            return {{}, {}};
        } else if (is_valtype(byte)) {
            ++iter;
            return {{}, {static_cast<valtype>(byte)}};
        } else {
            int64_t n = safe_read_sleb128<int64_t, 33>(iter);
            assert(n >= 0);
            assert(static_cast<uint64_t>(n) < types.size());
            return types[n];
        }
    }

    inline void call_function_info(const FunctionInfo &idx, uint8_t *return_to,
                                   std::function<void()> wasm_call);
    void interpret(uint8_t *iter);

    WasmValue interpret_const(safe_byte_iterator &iter, valtype expected);

    StackFrame &frame() { return frames.back(); }

  public:
    Instance(std::unique_ptr<uint8_t, void (*)(uint8_t *)> bytes,
             uint32_t length, const Imports &imports = {});

    ~Instance();

    const Exports &get_exports() { return exports; }
};

constexpr uint32_t stack_size = 5 * 1024 * 1024; // 5mb
} // namespace mitey