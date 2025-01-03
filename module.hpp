#pragma once

#include "spec.hpp"
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <tuple>
#include <variant>
#include <vector>

#ifdef __SIZEOF_INT128__
using cmp128_t = __int128_t;
#else
#include <array>
using cmp128_t = std::array<uint64_t, 2>;
#endif

namespace mitey {

template <typename T> struct function_traits;

template <typename R, typename... Args> struct function_traits<R (*)(Args...)> {
    using args = std::tuple<Args...>;
    using return_type = R;
};

template <template <typename...> class T, typename U>
constexpr bool is_specialization_of = false;

template <template <typename...> class T, typename... Us>
constexpr bool is_specialization_of<T, T<Us...>> = true;

class Instance;

union RuntimeType {
    struct {
        uint32_t n_params;
        uint32_t n_results;
        bool has_i32 : 1;
        bool has_i64 : 1;
        bool has_f32 : 1;
        bool has_f64 : 1;
        bool has_funcref : 1;
        bool has_externref : 1;
        uint64_t hash : 64 - 6;
    };
    cmp128_t cmp;

    bool operator==(const RuntimeType &other) const { return cmp == other.cmp; }

    template <typename Types, typename Iter>
    static RuntimeType read_blocktype(Types &types, Iter &iter) {
        constexpr uint8_t empty_type = 0x40;

        uint8_t byte = *iter;
        if (byte == empty_type) {
            ++iter;
            return RuntimeType{{0, 0, 0, 0, 0, 0, 0, 0, 0}};
        } else if (is_valtype(byte)) {
            ++iter;
            return RuntimeType{{0, 1, 0, 0, 0, 0, 0, 0, byte}};
        } else {
            int64_t n = read_leb128(iter);
            return types[n];
        }
    }

    static RuntimeType from_signature(const Signature &sig) {
        RuntimeType type;
        type.n_params = sig.params.size();
        type.n_results = sig.results.size();
        type.has_i32 = type.has_i64 = type.has_f32 = type.has_f64 =
            type.has_funcref = type.has_externref = false;
        type.hash = 0;
        for (valtype param : sig.params) {
            switch (param) {
            case valtype::i32:
                type.has_i32 = true;
                break;
            case valtype::i64:
                type.has_i64 = true;
                break;
            case valtype::f32:
                type.has_f32 = true;
                break;
            case valtype::f64:
                type.has_f64 = true;
                break;
            case valtype::funcref:
                type.has_funcref = true;
                break;
            case valtype::externref:
                type.has_externref = true;
                break;
            case valtype::null:
            case valtype::any:
                error<std::runtime_error>("invalid result type");
            }
            type.hash *= 16777619;
            type.hash ^= static_cast<uint64_t>(param);
        }
        type.hash *= 31;
        for (valtype result : sig.results) {
            switch (result) {
            case valtype::i32:
                type.has_i32 = true;
                break;
            case valtype::i64:
                type.has_i64 = true;
                break;
            case valtype::f32:
                type.has_f32 = true;
                break;
            case valtype::f64:
                type.has_f64 = true;
                break;
            case valtype::funcref:
                type.has_funcref = true;
                break;
            case valtype::externref:
                type.has_externref = true;
                break;
            case valtype::null:
            case valtype::any:
                error<std::runtime_error>("invalid result type");
            }
            type.hash *= 31;
            type.hash ^= static_cast<uint64_t>(result);
        }
        return type;
    }
};

struct FunctionInfo;

using Funcref = FunctionInfo *;
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

struct wasm_function {
    std::shared_ptr<Instance> instance;
    uint8_t *start = nullptr;
    uint32_t n_locals = 0;

    operator bool() const { return start != nullptr; }
};
// obtained via wasm_functionify<func>
using static_host_function = void(WasmValue *);
// obtained via wasm_functionify(func);
using dynamic_host_function = std::function<static_host_function>;

struct FunctionInfo {
    RuntimeType type;
    wasm_function wasm_fn;
    static_host_function *static_fn = nullptr;
    dynamic_host_function dyn_fn = nullptr;

    FunctionInfo() = default;

    FunctionInfo(Signature type, std::shared_ptr<Instance> instance,
                 uint8_t *start, std::vector<valtype> locals)
        : FunctionInfo(RuntimeType::from_signature(type), instance, start,
                       locals) {}
    FunctionInfo(RuntimeType type, std::shared_ptr<Instance> instance,
                 uint8_t *start, std::vector<valtype> locals)
        : type(type), wasm_fn{instance, start, (uint32_t)locals.size()} {}

    FunctionInfo(Signature type, dynamic_host_function fn)
        : FunctionInfo(RuntimeType::from_signature(type), fn) {}
    FunctionInfo(RuntimeType type, dynamic_host_function fn)
        : type(type), dyn_fn(fn) {}

    FunctionInfo(Signature type, static_host_function fn)
        : FunctionInfo(RuntimeType::from_signature(type), fn) {}
    FunctionInfo(RuntimeType type, static_host_function fn)
        : type(type), static_fn(fn) {}

    template <typename FunctionType> std::function<FunctionType> to() const {
        using Traits = function_traits<FunctionType *>;
        using ReturnType = typename Traits::return_type;

        bool call_static = static_fn != nullptr;

        return [this, call_static](auto... args) {
            constexpr bool is_multivalue =
                is_specialization_of<std::tuple, ReturnType>;

            constexpr size_t num_args =
                std::tuple_size_v<typename Traits::args>;
            constexpr size_t num_results = [=] {
                if constexpr (std::is_void_v<ReturnType>)
                    return 0;
                if constexpr (!is_multivalue)
                    return 1;
                else
                    return std::tuple_size_v<ReturnType>;
            }();

            void *buffer =
                alloca(sizeof(WasmValue) * std::max(num_args, num_results));
            WasmValue *stack = reinterpret_cast<WasmValue *>(buffer);

            push_tuple_to_wasm(std::make_tuple(args...), stack,
                               std::make_index_sequence<sizeof...(args)>{});

            if (call_static) {
                static_fn(stack);
            } else {
                dyn_fn(stack);
            }

            if constexpr (is_multivalue) {
                return [&]<size_t... I>(std::index_sequence<I...>) {
                    return ReturnType{(stack[I])...};
                }(std::make_index_sequence<num_results>{});
            } else if constexpr (!std::is_void_v<ReturnType>) {
                return stack[0];
            }
        };
    }

    std::function<std::vector<WasmValue>(const std::vector<WasmValue> &)>
    to() const {
        if (wasm_fn) {
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
            if (args.size() != type.n_params) {
                trap("invalid number of arguments");
            }

            // todo: this should absolutely not be a dynamic allocation but
            // alloca was throwing some shit
            auto stack = static_cast<WasmValue *>(
                alloca(sizeof(WasmValue) *
                       std::max(args.size(), (size_t)type.n_results)));
            std::copy(args.begin(), args.end(), stack);

            if (call_static) {
                static_fn(stack);
            } else {
                dyn_fn(stack);
            }

            return std::vector<WasmValue>(stack, stack + type.n_results);
        };
    }
};

class safe_byte_iterator {
    uint8_t *iter;
    uint8_t *end;

  public:
    safe_byte_iterator(uint8_t *ptr, size_t length);
    safe_byte_iterator(uint8_t *ptr, uint8_t *end);

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

enum class ImExDesc {
    func,
    table,
    mem,
    global,
};
static inline bool is_imexdesc(uint8_t byte) {
    return byte == static_cast<uint8_t>(ImExDesc::func) ||
           byte == static_cast<uint8_t>(ImExDesc::table) ||
           byte == static_cast<uint8_t>(ImExDesc::mem) ||
           byte == static_cast<uint8_t>(ImExDesc::global);
}

using ImportSpecifier = std::pair<std::string, std::string>;

struct FunctionShell {
    uint8_t *start;
    Signature type;
    std::vector<valtype> locals;
    std::optional<ImportSpecifier> import;
    bool is_declared = false;
};

struct TableShell {
    uint32_t min;
    uint32_t max;
    valtype type;
    std::optional<ImportSpecifier> import;
};

struct MemoryShell {
    uint32_t min;
    uint32_t max;
    bool exists;
    std::optional<ImportSpecifier> import;
};

struct GlobalShell {
    valtype type;
    mut mutability;
    uint8_t *initializer;
    std::optional<ImportSpecifier> import;
};

struct ExportShell {
    ImExDesc desc;
    uint32_t idx;
};

struct ElementShell {
    valtype type;
};

struct Segment {
    uint32_t memidx;
    std::span<uint8_t> data;
    uint8_t *initializer;
};

struct IfJump {
    uint8_t *else_;
    uint8_t *end;
};

class WasmTable;
class WasmMemory;
struct WasmGlobal;

using ExportValue =
    std::variant<FunctionInfo, std::shared_ptr<WasmTable>,
                 std::shared_ptr<WasmMemory>, std::shared_ptr<WasmGlobal>>;
using Exports = std::unordered_map<std::string, ExportValue>;
using ModuleImports = std::unordered_map<std::string, ExportValue>;
using Imports = std::unordered_map<std::string, ModuleImports>;

struct Function {};

struct Block {
    uint8_t *block_start;
};

struct Loop {};

struct If {
    uint8_t *if_start;
};

struct IfElse {
    uint8_t *if_start;
    uint8_t *else_start;
};

struct ControlFlow {
    std::vector<valtype> &expected;
    Signature &sig;
    bool polymorphized;
    std::variant<Function, Block, Loop, If, IfElse> construct;
};

class Module;
class WasmStack;
using ValidationHandler = void(Module &, safe_byte_iterator &, FunctionShell &,
                               WasmStack &, std::vector<ControlFlow> &);

// should return a shared_ptr to itself for easier lifetimes
class Module {
    friend class Instance;
    friend ValidationHandler validate_missing;
#define V(name, _, byte) friend ValidationHandler validate_##name;
    FOREACH_INSTRUCTION(V)
    FOREACH_MULTIBYTE_INSTRUCTION(V)
#undef V

    std::weak_ptr<Module> self;

    std::unique_ptr<uint8_t[]> bytes;

    std::vector<Signature> types;
    std::unordered_map<std::string, std::unordered_map<std::string, ImExDesc>>
        imports;
    std::vector<TableShell> tables;
    MemoryShell memory;
    std::vector<GlobalShell> globals;
    std::unordered_map<std::string, ExportShell> exports;
    uint32_t start;
    uint8_t *element_start;
    std::vector<ElementShell> elements;
    std::vector<FunctionShell> functions;
    uint32_t n_data;
    std::vector<Segment> data_segments;

    // locations of if else/end instructions
    std::unordered_map<uint8_t *, IfJump> if_jumps;
    // locations of block end instructions
    std::unordered_map<uint8_t *, uint8_t *> block_ends;

    void validate(safe_byte_iterator &iter, FunctionShell &fn);

    void validate_const(safe_byte_iterator &iter, valtype expected);

    Module(std::unique_ptr<uint8_t[]> _bytes);

    void initialize(uint32_t length);

  public:
    static constexpr uint32_t MAX_PAGES = 65536;
    static constexpr uint32_t MAX_LOCALS = 50000;

    static std::shared_ptr<Module> compile(std::unique_ptr<uint8_t[]> bytes,
                                           uint32_t length);

    std::shared_ptr<Instance> instantiate(const Imports &imports = {});

    void validate(uint8_t *end);
};

} // namespace mitey
