#pragma once

#include "spec.hpp"
#include <cassert>
#include <cstdint>
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
    mut mut;
    WasmValue value;
};

struct FunctionInfo {
    uint8_t *start;
    Signature type;
    std::vector<valtype> locals;
};

struct StackFrame {
    // locals (points to somewhere in the stack allocation)
    WasmValue *locals;
    // control stack (pointers to the place a br jumps to)
    std::vector<uint8_t *> control_stack;
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
    std::vector<StackFrame> frames;
    std::vector<FunctionInfo> functions;
    // value of globals
    std::vector<WasmGlobal> globals;
    // maps indices to the start of the function (mutable)
    std::vector<uint8_t *> tables;
    // maps element indices to the element in source bytes
    std::vector<uint8_t *> elements;
    std::vector<Signature> types;

    void interpret(uint32_t offset);
    void interpret(uint8_t *iter);

  public:
    Instance(std::unique_ptr<uint8_t, void (*)(uint8_t *)> bytes,
             uint32_t length);

    ~Instance();
};

constexpr uint32_t stack_size = 5 * 1024 * 1024; // 5mb
} // namespace Mitey