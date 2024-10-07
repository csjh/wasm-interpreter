#include <assert.h>
#include <cstring>
#include <memory>
#include <stdint.h>
#include <stdlib.h>
#include <vector>

namespace Mitey {
union WasmValue {
    int32_t i32;
    int64_t i64;
    float f32;
    double f64;
};

typedef uint8_t WasmType;

struct FunctionType {
    std::vector<WasmType> params;
    std::vector<WasmType> results;
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

class Instance {
    // source bytes
    std::unique_ptr<uint8_t, void (*)(uint8_t *)> bytes;
    // WebAssembly.Memory
    WasmMemory memory;
    // maps indices to the offset start of the function (immutable)
    std::vector<uint32_t> functions;
    // value of globals
    std::vector<WasmValue> globals;
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
                fn.params.push_back(iter[j]);
            }
            iter += n_params;

            uint32_t n_results = read_leb128(iter);
            fn.results.reserve(n_results);
            for (uint32_t j = 0; j < n_results; ++j) {
                fn.results.push_back(iter[j]);
            }
            iter += n_results;

            types.emplace_back(fn);
        }
    }

    skip_custom_section();

    // todo: import section

    skip_custom_section();

    // function section (is this even needed for non-validation purposes)
    // if (*iter == 3) {
    //     ++iter;
    //     uint32_t section_length = read_leb128(iter);
    //     uint32_t n_functions = read_leb128(iter);

    //     functions = new uint32_t[n_functions];
    //     for (uint32_t i = 0; i < n_functions; ++i) {
    //         functions[i] = read_leb128(iter);
    //     }
    // }

    skip_custom_section();

    // todo: table section

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

    // todo: global section

    skip_custom_section();

    // todo: export section

    skip_custom_section();

    // todo: start section

    skip_custom_section();

    // todo: element section

    skip_custom_section();

    // todo: code section

    skip_custom_section();

    // todo: data section

    skip_custom_section();

    // todo: data count section

    skip_custom_section();
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
