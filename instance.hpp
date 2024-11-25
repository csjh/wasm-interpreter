#pragma once

#include "module.hpp"
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

class WasmMemory {
    uint8_t *memory;
    uint32_t current;
    uint32_t maximum;

  public:
    static constexpr uint32_t MAX_PAGES = 65536;
    static constexpr uint32_t PAGE_SIZE = 65536;

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

// Helper to convert tuple to multiple values
template <typename Tuple, size_t... I>
void push_tuple_to_wasm(const Tuple &t, WasmValue *out,
                        std::index_sequence<I...>) {
    ((out[I] = std::get<I>(t)), ...);
}

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

    T *get_start() { return start; }
    void set_start(T *new_start) { start = new_start; }

    T *begin() { return start; }
    T *end() { return ptr; }
};

struct ElementSegment {
    valtype type;
    std::vector<WasmValue> elements;
};

template <typename T> class owned_span : protected std::unique_ptr<T[]> {
    size_t _size;

  public:
    owned_span() : _size(0) {}
    owned_span(size_t size)
        : std::unique_ptr<T[]>(std::make_unique<T[]>(size)), _size(size) {}

    T *data() { return this->get(); }
    T &operator[](size_t idx) { return this->get()[idx]; }
    size_t size() { return _size; }
};

class Instance {
    friend class Module;

    static constexpr uint32_t STACK_SIZE = 5 * 1024 * 1024; // 5mb
    static constexpr uint32_t MAX_DEPTH = 1000;

    Instance(const Instance &) = delete;
    Instance &operator=(const Instance &) = delete;
    Instance(Instance &&) = delete;
    Instance &operator=(Instance &&) = delete;

    std::shared_ptr<Module> module;
    std::weak_ptr<Instance> self;

    // WebAssembly.Memory
    std::shared_ptr<WasmMemory> memory;
    // internal stack
    tape<WasmValue> initial_stack;
    // function-specific frames
    tape<StackFrame> frames;
    // control stack
    tape<BrTarget> control_stack;
    // functions
    owned_span<FunctionInfo> functions;
    // types
    owned_span<RuntimeType> types;
    // locations of if else/end instructions
    std::unordered_map<uint8_t *, IfJump> if_jumps;
    // locations of block end instructions
    std::unordered_map<uint8_t *, uint8_t *> block_ends;
    // value of globals
    owned_span<std::shared_ptr<WasmGlobal>> globals;
    // maps element indices to the element initializers
    owned_span<ElementSegment> elements;
    // data segments
    owned_span<Segment> data_segments;
    // tables
    owned_span<std::shared_ptr<WasmTable>> tables;
    // exports from export section
    Exports exports;

    inline void call_function_info(const FunctionInfo &idx, uint8_t *return_to,
                                   tape<WasmValue> &stack,
                                   std::function<void()> wasm_call);
    void interpret(uint8_t *iter, tape<WasmValue> &);

    void entrypoint(const FunctionInfo &, tape<WasmValue> &);

    WasmValue interpret_const_inplace(uint8_t *iter) {
        return interpret_const(iter);
    }
    WasmValue interpret_const(uint8_t *&iter);

    StackFrame &frame() { return frames[-1]; }

    // makes a function run independently of the instance
    FunctionInfo externalize_function(const FunctionInfo &fn);

    Instance(std::shared_ptr<Module> module);

    void initialize(const Imports &imports);

  public:
    ~Instance();

    const Exports &get_exports() { return exports; }
};
} // namespace mitey