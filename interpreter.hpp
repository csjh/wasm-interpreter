#pragma once

#include "spec.hpp"
#include <cassert>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iostream>
#include <memory>
#include <unordered_map>
#include <variant>
#include <vector>

namespace mitey {
[[noreturn]] static inline void trap(std::string message) {
    throw trap_error(message);
}

class Instance;

struct IndirectFunction {
    Instance *instance;
    uint32_t funcidx;
    uint32_t typeidx;
};

using Funcref = IndirectFunction *;
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

    WasmValue() : u64(0) {}

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
    static const uint32_t MAX_PAGES = 65536;
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
    void memcpy(WasmTable &dst_table, uint32_t dst, uint32_t src,
                uint32_t length);
    void memset(uint32_t dst, WasmValue value, uint32_t length);
};

struct WasmGlobal {
    valtype type;
    mut _mut;
    WasmValue value;

    WasmGlobal(valtype type, mut _mut, WasmValue value)
        : type(type), _mut(_mut), value(value) {}
};

template <typename T> struct function_traits;

template <typename R, typename... Args> struct function_traits<R (*)(Args...)> {
    using args = std::tuple<Args...>;
    using return_type = R;
};

template <template <typename...> class T, typename U>
constexpr bool is_specialization_of = false;

template <template <typename...> class T, typename... Us>
constexpr bool is_specialization_of<T, T<Us...>> = true;

// Helper to convert tuple to multiple values
template <typename Tuple, size_t... I>
void push_tuple_to_wasm(const Tuple &t, WasmValue *out,
                        std::index_sequence<I...>) {
    ((out[I] = std::get<I>(t)), ...);
}

// obtained via wasm_functionify<func>
using static_host_function = void(WasmValue *);
// obtained via wasm_functionify(func);
using dynamic_host_function = std::function<static_host_function>;

template <typename F, typename Callable>
void call_with_stack(Callable &&func, WasmValue *stack) {
    using Fn = function_traits<F>;
    using FnArgs = typename Fn::args;
    using ReturnType = typename Fn::return_type;
    constexpr size_t num_args = std::tuple_size_v<FnArgs>;

    // Convert input arguments to tuple
    auto args = [&]<size_t... I>(std::index_sequence<I...>) {
        return FnArgs{(stack[I])...};
    }(std::make_index_sequence<num_args>{});

    if constexpr (std::is_void_v<ReturnType>) {
        std::apply(func, args);
    } else if constexpr (is_specialization_of<std::tuple, ReturnType>) {
        auto ret = std::apply(func, args);
        push_tuple_to_wasm(
            ret, stack,
            std::make_index_sequence<std::tuple_size_v<ReturnType>>{});
    } else {
        *stack = std::apply(func, args);
    }
}

template <auto func> void wasm_functionify(WasmValue *stack) {
    call_with_stack<decltype(func)>(func, stack);
}

template <typename F>
dynamic_host_function wasm_functionify(std::function<F> func) {
    return [func](WasmValue *stack) { call_with_stack<F *>(func, stack); };
}

struct FunctionInfo {
    uint8_t *start = nullptr;
    Signature type;
    std::vector<valtype> locals;
    static_host_function *static_fn = nullptr;
    dynamic_host_function dyn_fn = nullptr;

    FunctionInfo() = default;

    FunctionInfo(uint8_t *start, Signature type, std::vector<valtype> locals)
        : start(start), type(type), locals(locals) {}

    FunctionInfo(dynamic_host_function fn, Signature type)
        : type(type), dyn_fn(fn) {}

    FunctionInfo(static_host_function *fn, Signature type)
        : type(type), dyn_fn(fn) {}

    template <typename FunctionType> std::function<FunctionType> to() const {
        using Traits = function_traits<FunctionType>;
        using ReturnType = typename Traits::return_type;
        constexpr size_t num_args = std::tuple_size_v<typename Traits::args>;

        if (start) {
            trap("non-exported wasm functions cannot be called from the host");
        }
        if (!static_fn && !dyn_fn) {
            trap("function has no implementation");
        }
        if (static_fn && dyn_fn) {
            trap("function has both static and dynamic implementations");
        }

        bool call_static = static_fn != nullptr;

        return [this, call_static](auto... args) {
            if constexpr (std::is_void_v<ReturnType>) {
                WasmValue *stack = reinterpret_cast<WasmValue *>(
                    alloca(sizeof(WasmValue) * num_args));
                push_tuple_to_wasm(std::make_tuple(args...), stack,
                                   std::make_index_sequence<sizeof...(args)>{});

                if (call_static) {
                    static_fn(stack);
                } else {
                    dyn_fn(stack);
                }
            } else if constexpr (is_specialization_of<std::tuple, ReturnType>) {
                constexpr size_t num_results = std::tuple_size_v<ReturnType>;

                WasmValue *stack = reinterpret_cast<WasmValue *>(alloca(
                    sizeof(WasmValue) * std::max(num_args, num_results)));
                push_tuple_to_wasm(std::make_tuple(args...), stack,
                                   std::make_index_sequence<sizeof...(args)>{});
                if (call_static) {
                    static_fn(stack);
                } else {
                    dyn_fn(stack);
                }
                return [&]<size_t... I>(std::index_sequence<I...>) {
                    return ReturnType{(stack[I])...};
                }(std::make_index_sequence<num_results>{});
            } else {
                WasmValue *stack = reinterpret_cast<WasmValue *>(
                    alloca(sizeof(WasmValue) * num_args));
                push_tuple_to_wasm(std::make_tuple(args...), stack,
                                   std::make_index_sequence<sizeof...(args)>{});
                if (call_static) {
                    static_fn(stack);
                } else {
                    dyn_fn(stack);
                }
                return stack[0];
            }
        };
    }

    std::function<std::vector<WasmValue>(const std::vector<WasmValue> &)>
    to() const {
        if (start) {
            trap("non-exported wasm functions cannot be called from the host");
        }
        if (!static_fn && !dyn_fn) {
            trap("function has no implementation");
        }
        if (static_fn && dyn_fn) {
            trap("function has both static and dynamic implementations");
        }

        bool call_static = static_fn != nullptr;

        return [this, call_static](const std::vector<WasmValue> &args) {
            if (args.size() != type.params.size()) {
                trap("invalid number of arguments");
            }

            // todo: this should absolutely not be a dynamic allocation but
            // alloca was throwing some shit
            auto stack = static_cast<WasmValue *>(
                alloca(sizeof(WasmValue) *
                       std::max(args.size(), type.results.size())));
            std::copy(args.begin(), args.end(), stack);

            if (call_static) {
                static_fn(stack);
            } else {
                dyn_fn(stack);
            }

            return std::vector<WasmValue>(stack, stack + type.results.size());
        };
    }
};

struct BrTarget {
    WasmValue *stack;
    uint8_t *dest;
    uint32_t arity;
};

struct StackFrame {
    // start of locals (points to somewhere in the stack allocation)
    WasmValue *locals;
    // points to somewhere in the control stack
    BrTarget *control_stack;
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
    uint8_t operator[](ssize_t n) const;
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

template <typename T> class tape {
    T *start;
    T *ptr;
    T *_end;

  public:
    tape(T *start, size_t length)
        : start(start), ptr(start), _end(start + length) {}

    void push(const T &value) {
        if (ptr == _end) {
            trap("call stack exhausted");
        }
        *ptr++ = value;
    }
    T pop() { return *--ptr; }
    void clear() { ptr = start; }

    T &back() { return ptr[-1]; }
    T &operator[](ssize_t idx) { return ptr[idx]; }

    void operator=(T *new_ptr) { ptr = new_ptr; }
    void operator++() { *this += 1; }
    void operator++(int) { *this += 1; }
    void operator+=(ssize_t n) {
        ptr += n;
        if (ptr > _end) {
            trap("call stack exhausted");
        }
    }
    void operator--() { *this -= 1; }
    void operator--(int) { *this -= 1; }
    void operator-=(ssize_t n) { ptr -= n; }

    ssize_t size() { return ptr - start; }
    bool empty() { return ptr == start; }
    T *unsafe_ptr() { return ptr; }
    T *unsafe_ptr(ssize_t diff) { return ptr + diff; }

    T *get_start() { return start; }
    void set_start(T *new_start) { start = new_start; }

    T *begin() { return start; }
    T *end() { return ptr; }
};

class Instance {
    friend class Validator;

    static constexpr uint32_t MAX_LOCALS = 50000;
    static constexpr uint32_t STACK_SIZE = 5 * 1024 * 1024; // 5mb
    static constexpr uint32_t MAX_DEPTH = 1000;

    Instance(const Instance &) = delete;
    Instance &operator=(const Instance &) = delete;
    Instance(Instance &&) = delete;
    Instance &operator=(Instance &&) = delete;

    // source bytes
    std::unique_ptr<uint8_t, void (*)(uint8_t *)> bytes;
    // WebAssembly.Memory
    std::shared_ptr<WasmMemory> memory;
    // internal stack
    tape<WasmValue> initial_stack;
    // function-specific frames
    tape<StackFrame> frames;
    // control stack
    tape<BrTarget> control_stack;
    // function info
    std::vector<FunctionInfo> functions;
    // funcrefs corresponding to the above functions
    std::vector<IndirectFunction> funcrefs;
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
                                   tape<WasmValue> &stack,
                                   std::function<void()> wasm_call);
    void interpret(uint8_t *iter, tape<WasmValue> &);

    void entrypoint(const FunctionInfo &);
    void entrypoint(const FunctionInfo &, tape<WasmValue> &);

    WasmValue interpret_const(safe_byte_iterator &iter, valtype expected);

    StackFrame &frame() { return frames[-1]; }

    // makes a function run independently of the instance
    FunctionInfo externalize_function(const FunctionInfo &fn);

  public:
    Instance(std::unique_ptr<uint8_t, void (*)(uint8_t *)> bytes,
             uint32_t length, const Imports &imports = {});

    ~Instance();

    const Exports &get_exports() { return exports; }
};
} // namespace mitey