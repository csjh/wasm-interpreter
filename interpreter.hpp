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
class malformed_error : public std::runtime_error {
  public:
    malformed_error(const std::string &message) : std::runtime_error(message) {}
};

class trap_error : public std::runtime_error {
  public:
    trap_error(const std::string &message) : std::runtime_error(message) {}
};

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

  public:
    static const uint32_t PAGE_SIZE = 65536;

    WasmMemory();
    WasmMemory(uint32_t initial, uint32_t maximum);

    WasmMemory(const WasmMemory &) = delete;
    WasmMemory &operator=(const WasmMemory &) = delete;
    WasmMemory(WasmMemory &&) = delete;
    WasmMemory &operator=(WasmMemory &&) = delete;

    ~WasmMemory();

    uint32_t size();
    uint32_t grow(uint32_t delta);

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

    uint32_t size();
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

    Instance(const Instance &) = delete;
    Instance &operator=(const Instance &) = delete;
    Instance(Instance &&) = delete;
    Instance &operator=(Instance &&) = delete;

    // source bytes
    std::unique_ptr<uint8_t, void (*)(uint8_t *)> bytes;
    // WebAssembly.Memory
    WasmMemory memory;
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
    std::vector<WasmGlobal> globals;
    // maps element indices to the element initializers
    std::vector<std::vector<WasmValue>> elements;
    // types from type section
    std::vector<Signature> types;
    // exports from export section
    std::unordered_map<std::string, Export> exports;
    // stack start for debugging and emptyness assertions
    WasmValue *stack_start;
    // data segments
    std::vector<Segment> data_segments;
    // tables
    std::vector<WasmTable> tables;

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
            assert(static_cast<uint64_t>(n) < types.size());
            return types[n];
        }
    }

    void prepare_to_call(const FunctionInfo &idx, uint8_t *return_to);
    void interpret(uint8_t *iter);

    WasmValue interpret_const(uint8_t *&iter);

    template <typename T> void push_arg(T arg);
    template <typename ReturnType> ReturnType pop_result();

    StackFrame &frame() { return frames.back(); }

    template <typename Tuple, size_t... I>
    Tuple create_tuple(std::index_sequence<I...>);

    template <typename FuncPointer, typename... Args>
    std::invoke_result_t<FuncPointer, Args...> execute(uint32_t idx,
                                                       Args... args);

  public:
    Instance(std::unique_ptr<uint8_t, void (*)(uint8_t *)> bytes,
             uint32_t length);

    ~Instance();

    template <typename FuncPointer, typename... Args>
    std::invoke_result_t<FuncPointer, Args...> execute(const std::string &name,
                                                       Args... args) {
        auto exp = exports.find(name);
        if (exp == exports.end()) {
            throw std::out_of_range("Function not found");
        } else if (exp->second.desc != ExportDesc::func) {
            throw std::invalid_argument("Export is not a function");
        }

        return execute<FuncPointer>(exp->second.idx, args...);
    }

    template <string_literal fn_name, typename FuncPointer, typename... Args>
    std::invoke_result_t<FuncPointer, Args...> execute(Args... args) {
        return execute<FuncPointer>(fn_name.value, args...);
    }

    // mainly intended for tests
    std::vector<WasmValue> execute(const std::string &name,
                                   const std::vector<WasmValue> &args) {
        auto exp = exports.find(name);
        if (exp == exports.end()) {
            throw std::out_of_range("Function not found");
        } else if (exp->second.desc != ExportDesc::func) {
            throw std::invalid_argument("Export is not a function");
        }

        auto fn = functions[exp->second.idx];
        if (fn.type.params.size() != args.size()) {
            throw std::invalid_argument("Incorrect number of arguments");
        }

        for (auto &arg : args) {
            push_arg(arg);
        }

        prepare_to_call(fn, nullptr);
        interpret(fn.start);

        stack = stack_start;
        return std::vector<WasmValue>(stack, stack + fn.type.results.size());
    }
};

template <typename T> inline constexpr bool always_false = false;

template <template <typename...> class T, typename U>
constexpr bool is_specialization_of = false;

template <template <typename...> class T, typename... Us>
constexpr bool is_specialization_of<T, T<Us...>> = true;

template <typename Tuple, size_t... I>
Tuple Instance::create_tuple(std::index_sequence<I...>) {
    return std::make_tuple(
        static_cast<std::tuple_element_t<I, Tuple>>(stack[I])...);
}

// Helper function to pop and return the result
template <typename ReturnType> ReturnType Instance::pop_result() {
    if constexpr (is_specialization_of<std::tuple, ReturnType>) {
        constexpr size_t size = std::tuple_size_v<ReturnType>;

        if (stack - stack_start != size) [[unlikely]] {
            throw std::out_of_range("Incorrect number of results");
        }

        stack = stack_start;
        return create_tuple<ReturnType>(std::make_index_sequence<size>{});
    } else {
        if (stack - stack_start != 1) [[unlikely]] {
            throw std::out_of_range("Incorrect number of results");
        }

        return static_cast<ReturnType>(*--stack);
    }
}

// Helper function to push an argument onto the stack
template <typename T> void Instance::push_arg(T arg) {
    if constexpr (std::is_same_v<T, WasmValue>) {
        *stack++ = arg;
    } else if constexpr (std::is_same_v<T, int32_t> ||
                         std::is_same_v<T, uint32_t>) {
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

template <typename T> struct function_traits;

template <typename R, typename... Args> struct function_traits<R (*)(Args...)> {
    using args = std::tuple<Args...>;
    using return_type = R;
};

template <typename FuncPointer, typename... Args>
std::invoke_result_t<FuncPointer, Args...> Instance::execute(uint32_t idx,
                                                             Args... args) {
    using Fn = function_traits<FuncPointer>;
    using FnArgs = Fn::args;
    using ReturnType = Fn::return_type;

    if (idx >= functions.size()) {
        throw std::out_of_range("Function index out of range");
    }

    const auto &fn = functions[idx];

    if (sizeof...(Args) != fn.type.params.size()) {
        throw std::invalid_argument("Incorrect number of arguments");
    }

    // push arguments onto the stack, casting to FnArgs
    std::apply([&](auto... arg) { (push_arg(arg), ...); }, FnArgs(args...));

    prepare_to_call(fn, nullptr);
    interpret(fn.start);

    if constexpr (!std::is_same_v<ReturnType, void>) {
        return pop_result<ReturnType>();
    }
}

constexpr uint32_t stack_size = 5 * 1024 * 1024; // 5mb
} // namespace mitey