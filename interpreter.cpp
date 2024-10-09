#include <assert.h>
#include <cstring>
#include <memory>
#include <stdint.h>
#include <stdlib.h>
#include <vector>

namespace Mitey {
enum class valtype {
    // numtype
    i32 = 0x7f,
    i64 = 0x7e,
    f32 = 0x7d,
    f64 = 0x7c,

    // vectype
    v128 = 0x7b,

    // reftype
    funcref = 0x70,
    externref = 0x6f,
};

bool is_valtype(uint8_t byte) {
    return byte == static_cast<uint8_t>(valtype::i32) ||
           byte == static_cast<uint8_t>(valtype::i64) ||
           byte == static_cast<uint8_t>(valtype::f32) ||
           byte == static_cast<uint8_t>(valtype::f64);
}

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

struct FunctionType {
    std::vector<valtype> params;
    std::vector<valtype> results;
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

    template <typename T> T load(uint32_t offset) {
        return *reinterpret_cast<T *>(memory + offset);
    }
};

enum class mut {
    const_ = 0x0,
    var = 0x1,
};

bool is_mut(uint8_t byte) {
    return byte == static_cast<uint8_t>(mut::const_) ||
           byte == static_cast<uint8_t>(mut::var);
}

struct WasmGlobal {
    valtype type;
    mut mut;
    WasmValue value;
};

struct BrTarget {
    bool is_loop : 1;
    uint32_t byte : 31;
};

struct FunctionInfo {
    uint8_t *start;
    FunctionType type;
};

struct StackFrame {
    // locals (points to somewhere in the stack allocation)
    WasmValue *locals;
    // control stack
    std::vector<BrTarget> control_stack;
};

class Instance {
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
    std::vector<FunctionType> types;

    void interpret(uint32_t offset);
    void interpret(uint8_t *iter);

  public:
    Instance(std::unique_ptr<uint8_t, void (*)(uint8_t *)> bytes,
             uint32_t length);

    ~Instance();
};

uint64_t read_leb128(uint8_t *&iter) {
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

constexpr uint32_t stack_size = 5 * 1024 * 1024; // 5mb

Instance::Instance(std::unique_ptr<uint8_t, void (*)(uint8_t *)> _bytes,
                   uint32_t length)
    : bytes(std::move(_bytes)),
      stack(static_cast<WasmValue *>(malloc(stack_size))) {
    uint8_t *iter = bytes.get();
    assert(std::strncmp(reinterpret_cast<char *>(iter), "\0asm", 4) == 0);
    iter += 4;

    assert(*reinterpret_cast<uint32_t *>(iter) == 1);
    iter += sizeof(uint32_t);

    auto skip_custom_section = [&]() {
        while (*iter == 0) [[unlikely]] {
            ++iter;
            uint32_t length = *reinterpret_cast<uint32_t *>(iter);
            iter += sizeof(uint32_t) + length;
        }
    };

    skip_custom_section();

    // type section
    if (*iter == 1) {
        ++iter;
        uint32_t section_length = read_leb128(iter);
        uint32_t n_types = read_leb128(iter);

        types.reserve(n_types);

        for (uint32_t i = 0; i < n_types; ++i) {
            assert(*iter == 0x60);
            ++iter;

            FunctionType fn;

            uint32_t n_params = read_leb128(iter);
            fn.params.reserve(n_params);
            for (uint32_t j = 0; j < n_params; ++j) {
                assert(is_valtype(iter[j]));
                fn.params.push_back(static_cast<valtype>(iter[j]));
            }
            iter += n_params;

            uint32_t n_results = read_leb128(iter);
            fn.results.reserve(n_results);
            for (uint32_t j = 0; j < n_results; ++j) {
                assert(is_valtype(iter[j]));
                fn.results.push_back(static_cast<valtype>(iter[j]));
            }
            iter += n_results;

            types.emplace_back(fn);
        }
    }

    skip_custom_section();

    // todo: import section
    if (*iter == 2) {
        ++iter;
        uint32_t section_length = read_leb128(iter);
        iter += section_length;
    }

    skip_custom_section();

    // function type section
    if (*iter == 3) {
        ++iter;
        uint32_t section_length = read_leb128(iter);
        uint32_t n_functions = read_leb128(iter);

        functions.reserve(n_functions);

        for (uint32_t i = 0; i < n_functions; ++i) {
            functions.emplace_back(
                FunctionInfo{nullptr, types[read_leb128(iter)]});
        }
    }

    skip_custom_section();

    // todo: table section
    if (*iter == 4) {
        ++iter;
        uint32_t section_length = read_leb128(iter);
        iter += section_length;
    }

    skip_custom_section();

    // memory section
    if (*iter == 5) {
        ++iter;
        uint32_t section_length = read_leb128(iter);

        uint32_t n_memories = read_leb128(iter);
        assert(n_memories == 1);

        // Limits are encoded with a preceding flag indicating whether a maximum
        // is present.
        uint32_t flags = read_leb128(iter);
        assert(flags == 0 || flags == 1);

        uint32_t initial = read_leb128(iter);
        uint32_t maximum = flags == 1 ? read_leb128(iter) : initial;

        new (&memory) WasmMemory(initial, maximum);
    }

    skip_custom_section();

    // global section
    if (*iter == 6) {
        ++iter;
        uint32_t section_length = read_leb128(iter);
        uint32_t n_globals = read_leb128(iter);

        globals.reserve(n_globals);

        for (uint32_t i = 0; i < n_globals; ++i) {
            uint8_t maybe_type = *iter++;
            assert(is_valtype(maybe_type));
            valtype type = static_cast<valtype>(maybe_type);

            uint8_t maybe_mut = *iter++;
            assert(is_mut(maybe_mut));
            mut global_mut = static_cast<mut>(maybe_mut);

            // todo: change this when interpret actually has meaning
            WasmValue value{0};
            while (*iter++ != 0x0b) {
                // interpret(iter);
            }

            globals.emplace_back(WasmGlobal{type, global_mut, value});
        }
    }

    skip_custom_section();

    // todo: export section
    if (*iter == 7) {
        ++iter;
        uint32_t section_length = read_leb128(iter);
        iter += section_length;
    }

    skip_custom_section();

    // start section
    uint32_t start = -1;
    if (*iter == 8) {
        ++iter;
        uint32_t section_length = read_leb128(iter);
        start = read_leb128(iter);
    }

    skip_custom_section();

    // todo: element section
    if (*iter == 9) {
        ++iter;
        uint32_t section_length = read_leb128(iter);
        iter += section_length;
    }

    skip_custom_section();

    // code section
    if (*iter == 10) {
        ++iter;
        uint32_t section_length = read_leb128(iter);
        uint32_t n_functions = read_leb128(iter);

        functions.reserve(n_functions);

        for (uint32_t i = 0; i < n_functions; ++i) {
            uint32_t function_length = read_leb128(iter);
            functions[i].start = iter;
            iter += function_length;
        }
    }

    skip_custom_section();

    // todo: data section
    if (*iter == 11) {
        ++iter;
        uint32_t section_length = read_leb128(iter);
        iter += section_length;
    }

    skip_custom_section();

    // todo: data count section
    if (*iter == 12) {
        ++iter;
        uint32_t section_length = read_leb128(iter);
        iter += section_length;
    }

    skip_custom_section();

    // run start function
}

[[noreturn]] void trap(std::string message) {
    throw std::runtime_error(message);
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

bool is_instruction(uint8_t byte) {
    // todo: figure out best way for this
    return true;
}

void Instance::interpret(uint32_t offset) { interpret(bytes.get() + offset); }

void Instance::interpret(uint8_t *iter) {
    uint8_t byte = *iter++;
    assert(is_instruction(byte));

    auto push = [&](WasmValue value) { *stack++ = value; };
    auto pop = [&]() { return *--stack; };
    auto exec_br = [&](uint32_t depth) {
        BrTarget target;
        do {
            target = frames.back().control_stack.back();
            frames.back().control_stack.pop_back();
        } while (depth--);
        interpret(target.byte);
    };

#define UNARY_OP(type, op)                                                     \
    push(op pop().type);                                                       \
    break
#define UNARY_FN(type, fn)                                                     \
    push(fn(pop().type));                                                      \
    break
#define BINARY_OP(type, op)                                                    \
    push(pop().type op pop().type);                                            \
    break
#define BINARY_FN(type, fn) push(fn(pop().type, pop().type));

    using enum Instruction;
    switch (static_cast<Instruction>(byte)) {
    case unreachable:
        trap("unreachable");
        break;
    case nop:
        break;
    case block: {
        uint32_t block_type = read_leb128(iter);
        frames.back().control_stack.push_back(
            {false, static_cast<uint32_t>(iter - bytes.get())});
        break;
    }
    case loop: {
        uint32_t block_type = read_leb128(iter);
        frames.back().control_stack.push_back(
            {true, static_cast<uint32_t>(iter - bytes.get())});
        break;
    }
    case if_:
        // how do i skip to the else block? or vice versa?
        break;
    case else_:
        break;
    case end:
        frames.back().control_stack.pop_back();
        break;
    case br: {
        exec_br(read_leb128(iter));
        break;
    }
    case br_if: {
        uint32_t depth = read_leb128(iter);
        if (pop().u32)
            exec_br(depth);
        break;
    }
    case br_table: {
        uint32_t v = pop().u32;
        uint32_t n_targets = read_leb128(iter);
        uint32_t *depths = reinterpret_cast<uint32_t *>(
            alloca((n_targets + 1) * sizeof(uint32_t)));

        // <= because there's an extra for the default target
        for (uint32_t i = 0; i <= n_targets; ++i) {
            depths[i] = read_leb128(iter);
        }
        exec_br(depths[std::max(n_targets, v)]);
        break;
    }
    case return_:
        break;
    case call: {
        FunctionInfo &fn = functions[read_leb128(iter)];
        frames.push_back(StackFrame{stack - fn.type.params.size(), {}});
        interpret(fn.start);
        break;
    }
    case call_indirect:
        break;
    case drop:
        pop();
        break;
    case select: {
        WasmValue vtrue = pop();
        WasmValue vfalse = pop();
        push(pop().i32 ? vtrue : vfalse);
        break;
    }
    case localget:
        push(frames.back().locals[read_leb128(iter)]);
        break;
    case localset:
        frames.back().locals[read_leb128(iter)] = pop();
        break;
    case localtee:
        frames.back().locals[read_leb128(iter)] = *stack;
        break;
    case globalget:
        push(globals[read_leb128(iter)].value);
        break;
    case globalset:
        globals[read_leb128(iter)].value = pop();
        break;
    case i32load:
        break;
    case i64load:
        break;
    case f32load:
        break;
    case f64load:
        break;
    case i32load8_s:
        break;
    case i32load8_u:
        break;
    case i32load16_s:
        break;
    case i32load16_u:
        break;
    case i64load8_s:
        break;
    case i64load8_u:
        break;
    case i64load16_s:
        break;
    case i64load16_u:
        break;
    case i64load32_s:
        break;
    case i64load32_u:
        break;
    case i32store:
        break;
    case i64store:
        break;
    case f32store:
        break;
    case f64store:
        break;
    case i32store8:
        break;
    case i32store16:
        break;
    case i64store8:
        break;
    case i64store16:
        break;
    case i64store32:
        break;
    case memorysize: {
        uint32_t mem_idx = read_leb128(iter);
        push(memory.size());
        break;
    }
    case memorygrow: {
        uint32_t mem_idx = read_leb128(iter);
        push(memory.grow(pop().u32));
        break;
    }
    case i32const:
        push((int32_t)read_leb128(iter));
        break;
    case i64const:
        push((int64_t)read_leb128(iter));
        break;
    case f32const:
        push(*reinterpret_cast<float *>(iter));
        iter += sizeof(float);
        break;
    case f64const:
        push(*reinterpret_cast<double *>(iter));
        iter += sizeof(double);
        break;
    // clang-format off
    case i32eqz:       UNARY_OP (i32, 0 ==);
    case i64eqz:       UNARY_OP (i64, 0 ==);
    case i32eq:        BINARY_OP(i32, ==);
    case i64eq:        BINARY_OP(i64, ==);
    case i32ne:        BINARY_OP(i32, !=);
    case i64ne:        BINARY_OP(i64, !=);
    case i32lt_s:      BINARY_OP(i32, < );
    case i64lt_s:      BINARY_OP(i64, < );
    case i32lt_u:      BINARY_OP(u32, < );
    case i64lt_u:      BINARY_OP(u64, < );
    case i32gt_s:      BINARY_OP(i32, > );
    case i64gt_s:      BINARY_OP(i64, > );
    case i32gt_u:      BINARY_OP(u32, > );
    case i64gt_u:      BINARY_OP(u64, > );
    case i32le_s:      BINARY_OP(i32, <=);
    case i64le_s:      BINARY_OP(i64, <=);
    case i32le_u:      BINARY_OP(u32, <=);
    case i64le_u:      BINARY_OP(u64, <=);
    case i32ge_s:      BINARY_OP(i32, >=);
    case i64ge_s:      BINARY_OP(i64, >=);
    case i32ge_u:      BINARY_OP(u32, >=);
    case i64ge_u:      BINARY_OP(u64, >=);
    case f32eq:        BINARY_OP(f32, ==);
    case f64eq:        BINARY_OP(f64, ==);
    case f32ne:        BINARY_OP(f32, !=);
    case f64ne:        BINARY_OP(f64, !=);
    case f32lt:        BINARY_OP(f32, < );
    case f64lt:        BINARY_OP(f64, < );
    case f32gt:        BINARY_OP(f32, > );
    case f64gt:        BINARY_OP(f64, > );
    case f32le:        BINARY_OP(f32, <=);
    case f64le:        BINARY_OP(f64, <=);
    case f32ge:        BINARY_OP(f32, >=);
    case f64ge:        BINARY_OP(f64, >=);
    case i32clz:       UNARY_FN (u32, std::countl_zero);
    case i64clz:       UNARY_FN (u64, (uint64_t)std::countl_zero);
    case i32ctz:       UNARY_FN (u32, std::countr_zero);
    case i64ctz:       UNARY_FN (u64, (uint64_t)std::countr_zero);
    case i32popcnt:    UNARY_FN (u32, std::popcount);
    case i64popcnt:    UNARY_FN (u64, (uint64_t)std::popcount);
    case i32add:       BINARY_OP(i32, + );
    case i64add:       BINARY_OP(i64, + );
    case i32sub:       BINARY_OP(i32, - );
    case i64sub:       BINARY_OP(i64, - );
    case i32mul:       BINARY_OP(i32, * );
    case i64mul:       BINARY_OP(i64, * );
    case i32div_s:     BINARY_OP(i32, / );
    case i64div_s:     BINARY_OP(i64, / );
    case i32div_u:     BINARY_OP(u32, / );
    case i64div_u:     BINARY_OP(u64, / );
    case i32rem_s:     BINARY_OP(i32, % );
    case i64rem_s:     BINARY_OP(i64, % );
    case i32rem_u:     BINARY_OP(u32, % );
    case i64rem_u:     BINARY_OP(u64, % );
    case i32and:       BINARY_OP(u32, & );
    case i64and:       BINARY_OP(u64, & );
    case i32or:        BINARY_OP(u32, | );
    case i64or:        BINARY_OP(u64, | );
    case i32xor:       BINARY_OP(u32, ^ );
    case i64xor:       BINARY_OP(u64, ^ );
    case i32shl:       BINARY_OP(u32, <<);
    case i64shl:       BINARY_OP(u64, <<);
    case i32shr_s:     BINARY_OP(i32, >>);
    case i64shr_s:     BINARY_OP(i64, >>);
    case i32shr_u:     BINARY_OP(u32, >>);
    case i64shr_u:     BINARY_OP(u64, >>);
    case i32rotl:      BINARY_FN(u32, std::rotl);
    case i64rotl:      BINARY_FN(u64, std::rotl);
    case i32rotr:      BINARY_FN(u32, std::rotr);
    case i64rotr:      BINARY_FN(u64, std::rotr);
    case f32abs:       UNARY_FN (f32, std::abs);
    case f64abs:       UNARY_FN (f64, std::abs);
    case f32neg:       UNARY_OP (f32, -);
    case f64neg:       UNARY_OP (f64, -);
    case f32ceil:      UNARY_FN (f32, std::ceil);
    case f64ceil:      UNARY_FN (f64, std::ceil);
    case f32floor:     UNARY_FN (f32, std::floor);
    case f64floor:     UNARY_FN (f64, std::floor);
    case f32trunc:     UNARY_FN (f32, std::trunc);
    case f64trunc:     UNARY_FN (f64, std::trunc);
    case f32nearest:   UNARY_FN (f32, std::nearbyint);
    case f64nearest:   UNARY_FN (f64, std::nearbyint);
    case f32sqrt:      UNARY_FN (f32, std::sqrt);
    case f64sqrt:      UNARY_FN (f64, std::sqrt);
    case f32add:       BINARY_OP(f32, +);
    case f64add:       BINARY_OP(f64, +);
    case f32sub:       BINARY_OP(f32, -);
    case f64sub:       BINARY_OP(f64, -);
    case f32mul:       BINARY_OP(f32, *);
    case f64mul:       BINARY_OP(f64, *);
    case f32div:       BINARY_OP(f32, /);
    case f64div:       BINARY_OP(f64, /);
    case f32min:       BINARY_FN(f32, std::min);
    case f64min:       BINARY_FN(f64, std::min);
    case f32max:       BINARY_FN(f32, std::max);
    case f64max:       BINARY_FN(f64, std::max);
    case f32copysign:  BINARY_FN(f32, std::copysign);
    case f64copysign:  BINARY_FN(f64, std::copysign);
    case i32wrap_i64:      UNARY_OP(i64, (int32_t));
    case i64extend_i32_s:  UNARY_OP(i32, (int64_t));
    case i64extend_i32_u:  UNARY_OP(u32, (uint64_t));
    case i32trunc_f32_s:   UNARY_OP(f32, (int32_t));
    case i64trunc_f32_s:   UNARY_OP(f32, (int64_t));
    case i32trunc_f32_u:   UNARY_OP(f32, (uint32_t));
    case i64trunc_f32_u:   UNARY_OP(f32, (uint64_t));
    case i32trunc_f64_s:   UNARY_OP(f64, (int32_t));
    case i64trunc_f64_s:   UNARY_OP(f64, (int64_t));
    case i32trunc_f64_u:   UNARY_OP(f64, (uint32_t));
    case i64trunc_f64_u:   UNARY_OP(f64, (uint64_t));
    case f32convert_i32_s: UNARY_OP(i32, (float));
    case f64convert_i32_s: UNARY_OP(i32, (double));
    case f32convert_i32_u: UNARY_OP(u32, (float));
    case f64convert_i32_u: UNARY_OP(u32, (double));
    case f32convert_i64_s: UNARY_OP(i64, (float));
    case f64convert_i64_s: UNARY_OP(i64, (double));
    case f32convert_i64_u: UNARY_OP(u64, (float));
    case f64convert_i64_u: UNARY_OP(u64, (double));
    case f32demote_f64:    UNARY_OP(f64, (float));
    case f64promote_f32:   UNARY_OP(f32, (double));
    // without type assertions these are noops
    case i32reinterpret_f32: /* push(pop().i32); */ break;
    case f32reinterpret_i32: /* push(pop().f32); */ break;
    case i64reinterpret_f64: /* push(pop().i64); */ break;
    case f64reinterpret_i64: /* push(pop().f64); */ break;
    default: __builtin_unreachable();
    };
    // clang-format on
}

// todo: this should check stack is the base pointer
// won't be necessary after validation is added
Instance::~Instance() { free(stack); }
} // namespace Mitey

/*
sections:
Id | Section
-------------------
 0 | custom section
 1 | type section
 2 | import section
 3 | function section
 4 | table section
 5 | memory section
 6 | global section
 7 | export section
 8 | start section
 9 | element section
10 | code section
11 | data section
12 | data count section
*/
