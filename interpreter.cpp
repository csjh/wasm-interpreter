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

union WasmValue {
    int32_t i32;
    int64_t i64;
    float f32;
    double f64;
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

    void grow(uint32_t delta) {
        uint32_t new_current = current + delta;
        memory = (uint8_t *)realloc(memory, new_current * 65536);
        std::memset(memory + current * 65536, 0, delta * 65536);
        current = new_current;
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

class Instance {
    // source bytes
    std::unique_ptr<uint8_t, void (*)(uint8_t *)> bytes;
    // WebAssembly.Memory
    WasmMemory memory;
    // maps indices to the offset start of the function (immutable)
    std::vector<uint32_t> functions;
    // value of globals
    std::vector<WasmGlobal> globals;
    // maps indices to the offset start of the function (mutable)
    std::vector<uint32_t> tables;
    // maps element indices to the element offset in source bytes
    std::vector<uint32_t> elements;
    std::vector<FunctionType> types;

    Instance(std::unique_ptr<uint8_t, void (*)(uint8_t *)> bytes,
             uint32_t length);

    ~Instance();

    void interpret(uint32_t idx);
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

Instance::Instance(std::unique_ptr<uint8_t, void (*)(uint8_t *)> bytes,
                   uint32_t length)
    : bytes(std::move(bytes)) {
    uint8_t *iter = bytes.get();
    assert(std::strncmp(reinterpret_cast<char *>(iter), "\0asm", 4) == 0);
    iter += 4;

    assert(*reinterpret_cast<uint32_t *>(iter) == 1);
    iter += 4;

    auto skip_custom_section = [&]() {
        while (*iter == 0) [[unlikely]] {
            ++iter;
            uint32_t length = *reinterpret_cast<uint32_t *>(iter);
            iter += 4 + length;
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

    // todo: function section (is this even needed for non-validation purposes)
    if (*iter == 3) {
        ++iter;
        uint32_t section_length = read_leb128(iter);
        iter += section_length;
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

        memory = WasmMemory(initial, maximum);
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
            WasmValue value;
            interpret(iter - bytes.get());

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
            functions.push_back(iter - bytes.get());
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

Instance::~Instance() {}
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
