#pragma once

#include "spec.hpp"
#include <cassert>
#include <cstdint>
#include <cstring>
#include <memory>
#include <unordered_map>
#include <vector>

namespace Mitey {
// technically unsigned versions don't exist but easier to use if they're here
union WasmValue {
    int32_t i32;
    uint32_t u32;
    int64_t i64;
    uint64_t u64;
    float f32;
    double f64;

    WasmValue(int32_t i32) : i32(i32) {}
    WasmValue(uint32_t u32) : u32(u32) {}
    WasmValue(int64_t i64) : i64(i64) {}
    WasmValue(uint64_t u64) : u64(u64) {}
    WasmValue(float f32) : f32(f32) {}
    WasmValue(double f64) : f64(f64) {}
};

class WasmMemory {
    uint8_t *memory;
    uint32_t current;
    uint32_t maximum;

  public:
    WasmMemory() : current(0), maximum(0), memory(nullptr) {}

    WasmMemory(uint32_t initial, uint32_t maximum)
        : current(initial), maximum(maximum),
          memory(static_cast<uint8_t *>(
              calloc(initial * 65536, sizeof(uint8_t)))) {}

    ~WasmMemory() {
        if (memory) {
            free(memory);
        }
    }

    uint32_t size() { return current; }

    uint32_t grow(uint32_t delta) {
        uint32_t new_current = current + delta;
        assert(new_current <= maximum);

        uint8_t *new_memory = (uint8_t *)realloc(memory, new_current * 65536);
        if (new_memory == NULL)
            return -1;
        memory = new_memory;
        std::memset(memory + current * 65536, 0, delta * 65536);

        uint32_t old_current = current;
        current = new_current;
        return old_current;
    }

    template <typename T>
    T load(uint32_t ptr, uint32_t offset, uint32_t align) {
        uint8_t *effective = memory + ptr + offset;
        if (reinterpret_cast<uint64_t>(effective) % align != 0)
            __builtin_unreachable();
        T value;
        std::memcpy(&value, effective, sizeof(T));
        return value;
    }

    template <typename T>
    void store(uint32_t ptr, uint32_t offset, uint32_t align, T value) {
        uint8_t *effective = memory + ptr + offset;
        if (reinterpret_cast<uint64_t>(effective) % align != 0)
            __builtin_unreachable();
        std::memcpy(effective, &value, sizeof(T));
    }
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

class Instance {
    friend class Validator;

    // source bytes
    std::unique_ptr<uint8_t, void (*)(uint8_t *)> bytes;
    // WebAssembly.Memory
    WasmMemory memory;
    // internal stack
    WasmValue *stack;
    // function-specific frames
    StackFrame frame;
    // function info
    std::vector<FunctionInfo> functions;
    // locations of if else/end instructions
    std::unordered_map<uint8_t *, IfJump> if_jumps;
    // locations of block end instructions
    std::unordered_map<uint8_t *, uint8_t *> block_ends;
    // value of globals
    std::vector<WasmGlobal> globals;
    // maps indices to the start of the function (mutable)
    std::vector<uint8_t *> tables;
    // maps element indices to the element in source bytes
    std::vector<uint8_t *> elements;
    std::vector<Signature> types;

    Signature read_blocktype(uint8_t *&iter) {
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
            assert(n < types.size());
            return types[n];
        }
    }

    void interpret(uint8_t *iter);

    template <typename T> void push_arg(T arg);
    template <typename ReturnType> ReturnType pop_result();

    void invoke(uint32_t index, uint8_t *return_to);

  public:
    Instance(std::unique_ptr<uint8_t, void (*)(uint8_t *)> bytes,
             uint32_t length);

    ~Instance();

    template <uint32_t FunctionIndex, typename FuncPointer, typename... Args>
    std::invoke_result_t<FuncPointer, Args...> execute(Args... args);
};

template <typename T> inline constexpr bool always_false = false;

// Helper function to pop and return the result
template <typename ReturnType> ReturnType Instance::pop_result() {
    WasmValue result = *--stack;

    if constexpr (std::is_same_v<ReturnType, int32_t>) {
        return result.i32;
    } else if constexpr (std::is_same_v<ReturnType, uint32_t>) {
        return result.u32;
    } else if constexpr (std::is_same_v<ReturnType, int64_t>) {
        return result.i64;
    } else if constexpr (std::is_same_v<ReturnType, uint64_t>) {
        return result.u64;
    } else if constexpr (std::is_same_v<ReturnType, float>) {
        return result.f32;
    } else if constexpr (std::is_same_v<ReturnType, double>) {
        return result.f64;
    } else {
        static_assert(always_false<ReturnType>, "Unsupported return type");
    }
}

// Helper function to push an argument onto the stack
template <typename T> void Instance::push_arg(T arg) {
    if constexpr (std::is_same_v<T, int32_t> || std::is_same_v<T, uint32_t>) {
        *stack++ = static_cast<int32_t>(arg);
    } else if constexpr (std::is_same_v<T, int64_t> ||
                         std::is_same_v<T, uint64_t>) {
        *stack++ = static_cast<int64_t>(arg);
    } else if constexpr (std::is_same_v<T, float>) {
        *stack++ = arg;
    } else if constexpr (std::is_same_v<T, double>) {
        *stack++ = arg;
    } else {
        static_assert(always_false<T>, "Unsupported argument type");
    }
}

template <uint32_t FunctionIndex, typename FuncPointer, typename... Args>
std::invoke_result_t<FuncPointer, Args...> Instance::execute(Args... args) {
    using ReturnType = std::invoke_result_t<FuncPointer, Args...>;

    if (FunctionIndex >= functions.size()) {
        throw std::out_of_range("Function index out of range");
    }

    const auto &fn = functions[FunctionIndex];

    if (sizeof...(Args) != fn.type.params.size()) {
        throw std::invalid_argument("Incorrect number of arguments");
    }

    (push_arg(args), ...);
    invoke(FunctionIndex, nullptr);

    return pop_result<ReturnType>();
}

constexpr uint32_t stack_size = 5 * 1024 * 1024; // 5mb
} // namespace Mitey