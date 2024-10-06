#include <assert.h>
#include <cstring>
#include <memory>
#include <stdint.h>

namespace Mitey {
union WasmValue {
    int32_t i32;
    int64_t i64;
    float f32;
    double f64;
};

struct FunctionType {
    uint32_t n_params;
    uint8_t *params;
    uint32_t n_results;
    uint8_t *results;
};

class Instance {
    std::unique_ptr<uint8_t, void (*)(uint8_t *)> bytes;
    uint8_t *memory;
    uint32_t *functions;
    WasmValue *globals;
    uint32_t *tables;
    uint8_t **elements;
    FunctionType *types;

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

        types = new FunctionType[n_types];

        for (uint32_t i = 0; i < n_types; ++i) {
            assert(*iter == 0x60);
            ++iter;

            FunctionType fn = {};

            fn.n_params = read_leb128(iter);
            fn.params = new uint8_t[fn.n_params];
            for (uint32_t j = 0; j < fn.n_params; ++j) {
                types->params[j] = iter[j];
            }
            iter += fn.n_params;

            fn.n_results = read_leb128(iter);
            fn.results = new uint8_t[fn.n_results];
            for (uint32_t j = 0; j < fn.n_results; ++j) {
                fn.results[j] = iter[j];
            }
            iter += fn.n_results;

            types[i] = fn;
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

    // todo: memory section

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

Instance::~Instance() { delete[] types; }
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
