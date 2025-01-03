#include "module.hpp"
#include "instance.hpp"
#include "spec.hpp"
#include <algorithm>
#include <limits>
#include <variant>

#ifdef WASM_DEBUG
#include <iostream>
#endif

namespace mitey {
safe_byte_iterator::safe_byte_iterator(uint8_t *ptr, size_t length)
    : iter(ptr), end(ptr + length) {}

safe_byte_iterator::safe_byte_iterator(uint8_t *ptr, uint8_t *end)
    : iter(ptr), end(end) {}

uint8_t safe_byte_iterator::operator*() const {
    if (iter >= end) {
        error<malformed_error>("unexpected end");
    }
    return *iter;
}

uint8_t safe_byte_iterator::operator[](ssize_t n) const {
    if (iter + n >= end) {
        error<malformed_error>("unexpected end");
    }
    return iter[n];
}

safe_byte_iterator &safe_byte_iterator::operator++() {
    ++iter;
    return *this;
}

safe_byte_iterator safe_byte_iterator::operator++(int) {
    return safe_byte_iterator(iter++, end);
}

safe_byte_iterator safe_byte_iterator::operator+(size_t n) const {
    return safe_byte_iterator(iter + n, end);
}

safe_byte_iterator &safe_byte_iterator::operator+=(size_t n) {
    iter += n;
    return *this;
}

ptrdiff_t safe_byte_iterator::operator-(safe_byte_iterator other) const {
    return iter - other.iter;
}

ptrdiff_t safe_byte_iterator::operator-(const uint8_t *other) const {
    return iter - other;
}

bool safe_byte_iterator::operator<(safe_byte_iterator other) const {
    return iter < other.iter;
}

uint8_t *safe_byte_iterator::get_with_at_least(size_t n) const {
    if (!has_n_left(n)) {
        error<malformed_error>("length out of bounds");
    }
    return iter;
}

bool safe_byte_iterator::empty() const { return iter == end; }

bool safe_byte_iterator::has_n_left(size_t n) const { return iter + n <= end; }

std::tuple<uint32_t, uint32_t> get_limits(safe_byte_iterator &iter,
                                          uint32_t upper_limit) {
    auto flags = safe_read_leb128<uint32_t, 1>(iter);
    auto initial = safe_read_leb128<uint32_t>(iter);
    auto max = flags == 1 ? safe_read_leb128<uint32_t>(iter) : upper_limit;
    return {initial, max};
}

std::tuple<uint32_t, uint32_t> get_memory_limits(safe_byte_iterator &iter) {
    auto [initial, max] = get_limits(iter, Module::MAX_PAGES);
    if (initial > Module::MAX_PAGES || max > Module::MAX_PAGES) {
        error<validation_error>(
            "memory size must be at most 65536 pages (4GiB)");
    }
    if (max < initial) {
        error<validation_error>(
            "size minimum must not be greater than maximum");
    }
    return {initial, max};
}

std::tuple<uint32_t, uint32_t> get_table_limits(safe_byte_iterator &iter) {
    auto [initial, max] =
        get_limits(iter, std::numeric_limits<uint32_t>::max());
    if (max < initial) {
        error<validation_error>(
            "size minimum must not be greater than maximum");
    }
    return {initial, max};
}

void Module::validate_const(safe_byte_iterator &iter, valtype expected) {
    std::vector<valtype> stack_types;

#define OP(ty, op)                                                             \
    {                                                                          \
        if (stack_types.size() < 2) {                                          \
            error<validation_error>("type mismatch");                          \
        }                                                                      \
        if (stack_types[stack_types.size() - 1] != stack_types.back()) {       \
            error<validation_error>("type mismatch");                          \
        }                                                                      \
        if (stack_types.back() != valtype::ty) {                               \
            error<validation_error>("type mismatch");                          \
        }                                                                      \
        stack_types.pop_back();                                                \
        break;                                                                 \
    }
#define I32_OP(op) OP(i32, op)
#define I64_OP(op) OP(i64, op)

    while (1) {
        auto byte = *iter++;
#ifdef WASM_DEBUG
        std::cerr << "reading instruction " << instructions[byte].c_str()
                  << " at " << iter - bytes.get() << std::endl;
#endif

        using enum Instruction;
        if (static_cast<Instruction>(byte) == end) {
            break;
        }
        switch (static_cast<Instruction>(byte)) {
        case i32const:
            safe_read_sleb128<int32_t>(iter);
            stack_types.push_back(valtype::i32);
            break;
        case i64const:
            safe_read_sleb128<int64_t>(iter);
            stack_types.push_back(valtype::i64);
            break;
        case f32const: {
            iter += sizeof(float);
            stack_types.push_back(valtype::f32);
            break;
        }
        case f64const: {
            iter += sizeof(double);
            stack_types.push_back(valtype::f64);
            break;
        }
        case globalget: {
            auto global_idx = safe_read_leb128<uint32_t>(iter);
            if (global_idx >= globals.size() || !globals[global_idx].import) {
                error<validation_error>("unknown global");
            }
            if (globals[global_idx].mutability != mut::const_) {
                error<validation_error>("constant expression required");
            }
            stack_types.push_back(globals[global_idx].type);
            break;
        }
        case i32add:
            I32_OP(+);
        case i32sub:
            I32_OP(-);
        case i32mul:
            I32_OP(*);
        case i64add:
            I64_OP(+);
        case i64sub:
            I64_OP(-);
        case i64mul:
            I64_OP(*);
        case ref_null: {
            auto reftype = safe_read_leb128<uint32_t>(iter);
            if (!is_reftype(reftype)) {
                error<validation_error>("type mismatch");
            }
            stack_types.push_back(static_cast<valtype>(reftype));
            break;
        }
        case ref_func: {
            auto func_idx = safe_read_leb128<uint32_t>(iter);
            if (func_idx >= functions.size()) {
                error<validation_error>("unknown function");
            }
            // implicit declaration
            functions[func_idx].is_declared = true;
            stack_types.push_back(valtype::funcref);
            break;
        }
        default:
            if (is_instruction(byte)) {
                error<validation_error>("constant expression required");
            } else {
                error<malformed_error>("illegal opcode");
            }
        }
    }

#undef OP
#undef I32_OP
#undef I64_OP

    if (stack_types.size() != 1 || stack_types[0] != expected) {
        error<validation_error>("type mismatch");
    }
}

std::shared_ptr<Module> Module::compile(std::unique_ptr<uint8_t[]> bytes,
                                        uint32_t length) {
    auto module = std::shared_ptr<Module>(new Module(std::move(bytes)));
    module->self = module;
    module->initialize(length);
    return module;
}

std::shared_ptr<Instance> Module::instantiate(const Imports &imports) {
    auto instance = std::shared_ptr<Instance>(new Instance(this->self.lock()));
    instance->self = instance;
    instance->initialize(imports);
    return instance;
}

Module::Module(std::unique_ptr<uint8_t[]> _bytes)
    : bytes(std::move(_bytes)), memory{} {}

void Module::initialize(uint32_t length) {
    if (length < 4) {
        error<malformed_error>("unexpected end");
    }

    safe_byte_iterator iter(bytes.get(), length);

    if (std::memcmp(reinterpret_cast<char *>(iter.get_with_at_least(4)),
                    "\0asm", 4) != 0) {
        error<malformed_error>("magic header not detected");
    }
    iter += 4;

    if (length < 8) {
        error<malformed_error>("unexpected end");
    }

    if (*reinterpret_cast<uint32_t *>(iter.get_with_at_least(4)) != 1) {
        error<malformed_error>("unknown binary version");
    }
    iter += sizeof(uint32_t);

    auto skip_custom_section = [&]() {
        while (!iter.empty() && *iter == 0) [[unlikely]] {
            ++iter;
            auto section_length = safe_read_leb128<uint32_t>(iter);
            if (!iter.has_n_left(section_length)) {
                error<malformed_error>("length out of bounds");
            }

            auto start = iter;

            auto name_length = safe_read_leb128<uint32_t>(iter);
            if (!is_valid_utf8(iter.get_with_at_least(name_length),
                               name_length)) {
                error<malformed_error>("malformed UTF-8 encoding");
            }

            if (start + section_length < iter) {
                error<malformed_error>("unexpected end");
            }

            iter = start + section_length;
        }
    };

    auto section = [&](
                       uint32_t id, std::function<void()> body,
                       std::function<void()> else_ = [] {}) {
        if (!iter.empty() && *iter == id) {
            ++iter;
            auto section_length = safe_read_leb128<uint32_t>(iter);
            if (!iter.has_n_left(section_length)) {
                error<malformed_error>("length out of bounds");
            }
            auto section_start = iter;

            body();

            if (iter - section_start != section_length) {
                error<malformed_error>("section size mismatch");
            }

            // todo: remove this when validation separates
            if (!iter.empty() && *iter == id) {
                error<malformed_error>("unexpected content after last section");
            }
        } else if (!iter.empty() && *iter > 12) {
            error<malformed_error>("malformed section id");
        } else {
            else_();
        }
    };

    skip_custom_section();

    // type section
    section(1, [&] {
        auto n_types = safe_read_leb128<uint32_t>(iter);

        types.reserve(n_types);

        for (uint32_t i = 0; i < n_types; ++i) {
            if (iter.empty()) {
                error<malformed_error>("unexpected end of section or function");
            }

            if (*iter != 0x60) {
                error<malformed_error>("integer representation too long");
                // error<validation_error>("invalid function type");
            }
            ++iter;

            Signature fn{{}, {}};

            auto n_params = safe_read_leb128<uint32_t>(iter);
            fn.params.reserve(n_params);
            for (uint32_t j = 0; j < n_params; ++j) {
                if (!is_valtype(iter[j])) {
                    error<validation_error>("invalid parameter type");
                }
                fn.params.push_back(static_cast<valtype>(iter[j]));
            }
            iter += n_params;

            auto n_results = safe_read_leb128<uint32_t>(iter);
            fn.results.reserve(n_results);
            for (uint32_t j = 0; j < n_results; ++j) {
                if (!is_valtype(iter[j])) {
                    error<validation_error>("invalid result type");
                }
                fn.results.push_back(static_cast<valtype>(iter[j]));
            }
            iter += n_results;

            types.emplace_back(fn);
        }
    });

    skip_custom_section();

    uint32_t n_fn_imports = 0;

    // import section
    section(2, [&] {
        auto n_imports = safe_read_leb128<uint32_t>(iter);

        for (uint32_t i = 0; i < n_imports; i++) {
            if (iter.empty()) {
                error<malformed_error>("unexpected end of section or function");
            }

            auto module_len = safe_read_leb128<uint32_t>(iter);
            if (!is_valid_utf8(iter.get_with_at_least(module_len),
                               module_len)) {
                error<malformed_error>("malformed UTF-8 encoding");
            }
            std::string module(
                reinterpret_cast<char *>(iter.get_with_at_least(module_len)),
                module_len);
            iter += module_len;

            auto field_len = safe_read_leb128<uint32_t>(iter);
            if (!is_valid_utf8(iter.get_with_at_least(field_len), field_len)) {
                error<malformed_error>("malformed UTF-8 encoding");
            }
            std::string field(
                reinterpret_cast<char *>(iter.get_with_at_least(field_len)),
                field_len);
            iter += field_len;

            auto kind = *iter++;
            if (!is_imexdesc(kind)) {
                error<malformed_error>("malformed import kind");
            }
            auto desc = static_cast<ImExDesc>(kind);
            imports[module][field] = desc;

            auto specifier = std::make_optional(std::make_pair(module, field));

            if (desc == ImExDesc::func) {
                // func
                auto typeidx = safe_read_leb128<uint32_t>(iter);
                if (typeidx >= types.size()) {
                    error<validation_error>("unknown type");
                }
                functions.push_back({nullptr, types[typeidx], {}, specifier});
                n_fn_imports++;
            } else if (desc == ImExDesc::table) {
                // table
                auto reftype = safe_read_leb128<uint32_t>(iter);
                if (!is_reftype(reftype)) {
                    error<malformed_error>("malformed reference type");
                }

                auto [initial, max] = get_table_limits(iter);
                tables.push_back(
                    {initial, max, static_cast<valtype>(reftype), specifier});
            } else if (desc == ImExDesc::mem) {
                // mem
                if (memory.exists) {
                    error<validation_error>("multiple memories");
                }

                auto [initial, max] = get_memory_limits(iter);
                this->memory = {initial, max, true, specifier};
            } else if (desc == ImExDesc::global) {
                // global
                auto maybe_valtype = safe_read_leb128<uint32_t>(iter);
                if (!is_valtype(maybe_valtype)) {
                    error<malformed_error>("invalid global type");
                }
                auto mutability = *iter++;
                if (!is_mut(mutability)) {
                    error<malformed_error>("malformed mutability");
                }

                globals.push_back({static_cast<valtype>(maybe_valtype),
                                   static_cast<mut>(mutability), nullptr,
                                   specifier});
            }
        }
    });

    skip_custom_section();

    // function type section
    section(3, [&] {
        auto n_functions = safe_read_leb128<uint32_t>(iter);

        functions.reserve(n_functions);

        for (uint32_t i = 0; i < n_functions; ++i) {
            if (iter.empty()) {
                error<malformed_error>("unexpected end of section or function");
            }

            auto type_idx = safe_read_leb128<uint32_t>(iter);
            if (type_idx >= types.size()) {
                error<validation_error>("unknown type");
            }
            functions.push_back({nullptr, types[type_idx], {}, std::nullopt});
        }
    });

    skip_custom_section();

    // table section
    section(4, [&] {
        auto n_tables = safe_read_leb128<uint32_t>(iter);
        tables.reserve(n_tables);

        for (uint32_t i = 0; i < n_tables; ++i) {
            if (iter.empty()) {
                error<malformed_error>("unexpected end of section or function");
            }

            auto elem_type = *iter++;
            if (!is_reftype(elem_type)) {
                error<validation_error>("invalid table element type");
            }

            auto [initial, max] = get_table_limits(iter);
            tables.push_back(
                {initial, max, static_cast<valtype>(elem_type), std::nullopt});
        }
    });

    skip_custom_section();

    // memory section
    section(5, [&] {
        auto n_memories = safe_read_leb128<uint32_t>(iter);
        if (n_memories > 1) {
            error<validation_error>("multiple memories");
        } else if (n_memories == 1) {
            if (iter.empty()) {
                error<malformed_error>("unexpected end of section or function");
            }
            if (memory.exists) {
                error<validation_error>("multiple memories");
            }

            auto [initial, max] = get_memory_limits(iter);
            memory = {initial, max, true, std::nullopt};
        }
    });

    skip_custom_section();

    // global section
    section(6, [&] {
        auto n_globals = safe_read_leb128<uint32_t>(iter);

        globals.reserve(n_globals);

        for (uint32_t i = 0; i < n_globals; ++i) {
            if (iter.empty()) {
                error<malformed_error>("unexpected end of section or function");
            }

            auto maybe_type = *iter++;
            if (!is_valtype(maybe_type)) {
                error<malformed_error>("invalid global type");
            }
            auto type = static_cast<valtype>(maybe_type);

            auto maybe_mut = *iter++;
            if (!is_mut(maybe_mut)) {
                error<malformed_error>("malformed mutability");
            }
            auto global_mut = static_cast<mut>(maybe_mut);

            globals.push_back(
                {type, global_mut, iter.unsafe_ptr(), std::nullopt});

            validate_const(iter, type);
        }
    });

    skip_custom_section();

    // export section
    section(7, [&] {
        auto n_exports = safe_read_leb128<uint32_t>(iter);

        for (uint32_t i = 0; i < n_exports; ++i) {
            if (iter.empty()) {
                error<malformed_error>("unexpected end of section or function");
            }

            auto name_len = safe_read_leb128<uint32_t>(iter);
            std::string name(
                reinterpret_cast<char *>(iter.get_with_at_least(name_len)),
                name_len);
            iter += name_len;

            auto desc = *iter++;
            if (!is_imexdesc(desc)) {
                error<validation_error>("invalid export description");
            }
            auto export_desc = static_cast<ImExDesc>(desc);

            auto idx = safe_read_leb128<uint32_t>(iter);

            if (exports.contains(name)) {
                error<validation_error>("duplicate export name");
            }

            if (export_desc == ImExDesc::func) {
                if (idx >= functions.size()) {
                    error<validation_error>("unknown function");
                }
                // implicit declaration
                functions[idx].is_declared = true;
            } else if (export_desc == ImExDesc::table) {
                if (idx >= tables.size()) {
                    error<validation_error>("unknown table");
                }
            } else if (export_desc == ImExDesc::mem) {
                if (idx != 0 || !memory.exists) {
                    error<validation_error>("unknown memory");
                }
            } else if (export_desc == ImExDesc::global) {
                if (idx >= globals.size()) {
                    error<validation_error>("unknown global");
                }
            }
            exports[name] = {export_desc, idx};
        }
    });

    skip_custom_section();

    section(
        8,
        [&] {
            start = safe_read_leb128<uint32_t>(iter);
            if (start >= functions.size()) {
                error<validation_error>("unknown function");
            }
        },
        [&] { start = std::numeric_limits<uint32_t>::max(); });

    skip_custom_section();

    // element section
    section(9, [&] {
        auto n_elements = safe_read_leb128<uint32_t>(iter);

        elements.reserve(n_elements);

        element_start = iter.unsafe_ptr();
        for (uint32_t i = 0; i < n_elements; i++) {
            if (iter.empty()) {
                error<malformed_error>("unexpected end of section or function");
            }

            auto flags = safe_read_leb128<uint32_t>(iter);
            if (flags & ~0b111) {
                error<validation_error>("invalid element flags");
            }

            if (flags & 1) {
                if (flags & 0b10) {
                    if (flags & 0b100) {
                        // flags = 7
                        // characteristics: declarative, elem type + exprs
                        auto maybe_reftype = *iter++;
                        if (!is_reftype(maybe_reftype)) {
                            error<malformed_error>("malformed reference type");
                        }
                        auto reftype = static_cast<valtype>(maybe_reftype);
                        auto n_elements = safe_read_leb128<uint32_t>(iter);
                        for (uint32_t j = 0; j < n_elements; j++) {
                            // validate_const sets is_declared
                            validate_const(iter, reftype);
                        }
                        elements.emplace_back(ElementShell{reftype});
                    } else {
                        // flags = 3
                        // characteristics: declarative, elem kind + indices
                        auto elemkind = *iter++;
                        if (elemkind != 0) {
                            error<validation_error>("invalid elemkind");
                        }
                        auto n_elements = safe_read_leb128<uint32_t>(iter);
                        for (uint32_t j = 0; j < n_elements; j++) {
                            uint32_t elem_idx =
                                safe_read_leb128<uint32_t>(iter);
                            if (elem_idx >= functions.size()) {
                                error<validation_error>("unknown function");
                            }
                            functions[elem_idx].is_declared = true;
                        }
                        elements.emplace_back(ElementShell{valtype::funcref});
                    }
                } else {
                    if (flags & 0b100) {
                        // flags = 5
                        // characteristics: passive, elem type + exprs
                        auto maybe_reftype = *iter++;
                        if (!is_reftype(maybe_reftype)) {
                            error<malformed_error>("malformed reference type");
                        }
                        auto reftype = static_cast<valtype>(maybe_reftype);
                        auto n_elements = safe_read_leb128<uint32_t>(iter);
                        for (uint32_t j = 0; j < n_elements; j++) {
                            validate_const(iter, reftype);
                        }
                        elements.emplace_back(ElementShell{reftype});
                    } else {
                        // flags = 1
                        // characteristics: passive, elem kind + indices
                        auto elemkind = *iter++;
                        if (elemkind != 0) {
                            error<validation_error>("invalid elemkind");
                        }
                        auto n_elements = safe_read_leb128<uint32_t>(iter);
                        for (uint32_t j = 0; j < n_elements; j++) {
                            uint32_t elem_idx =
                                safe_read_leb128<uint32_t>(iter);
                            if (elem_idx >= functions.size()) {
                                error<validation_error>("unknown function");
                            }
                            // implicit declaration
                            functions[elem_idx].is_declared = true;
                        }
                        elements.emplace_back(ElementShell{valtype::funcref});
                    }
                }
            } else {
                uint32_t table_idx =
                    flags & 0b10 ? safe_read_leb128<uint32_t>(iter) : 0;
                if (table_idx >= tables.size()) {
                    error<validation_error>("unknown table");
                }

                valtype reftype;

                /* auto offset = */ validate_const(iter, valtype::i32);
                auto reftype_or_elemkind = flags & 0b10 ? *iter++ : 256;
                auto n_elements = safe_read_leb128<uint32_t>(iter);

                if (flags & 0b100) {
                    // flags = 4 or 6
                    // characteristics: active, elem type + exprs
                    if (reftype_or_elemkind == 256)
                        reftype_or_elemkind =
                            static_cast<uint16_t>(valtype::funcref);
                    if (!is_reftype(reftype_or_elemkind)) {
                        error<malformed_error>("malformed reference type");
                    }
                    reftype = static_cast<valtype>(reftype_or_elemkind);
                    if (tables[table_idx].type != reftype) {
                        error<validation_error>("type mismatch");
                    }
                    for (uint32_t j = 0; j < n_elements; j++) {
                        validate_const(iter, reftype);
                    }
                } else {
                    if (reftype_or_elemkind == 256)
                        reftype_or_elemkind = 0;
                    if (reftype_or_elemkind != 0) {
                        error<validation_error>("invalid elemkind");
                    }
                    reftype = valtype::funcref;
                    if (tables[table_idx].type != reftype) {
                        error<validation_error>("type mismatch");
                    }
                    // flags = 0 or 2
                    // characteristics: active, elem kind + indices
                    for (uint32_t j = 0; j < n_elements; j++) {
                        auto elem_idx = safe_read_leb128<uint32_t>(iter);
                        if (elem_idx >= functions.size()) {
                            error<validation_error>("unknown function");
                        }
                        // implicit declaration
                        functions[elem_idx].is_declared = true;
                    }
                }
                elements.emplace_back(ElementShell{reftype});
            }
        }
    });

    skip_custom_section();

    // data count section
    n_data = std::numeric_limits<uint32_t>::max();
    auto has_data_count = false;
    section(12, [&] {
        n_data = safe_read_leb128<uint32_t>(iter);
        has_data_count = true;
    });

    skip_custom_section();

    // code section
    section(
        10,
        [&] {
            auto n_functions = safe_read_leb128<uint32_t>(iter);

            if (n_functions + n_fn_imports != functions.size()) {
                error<malformed_error>(
                    "function and code section have inconsistent lengths");
            }

            for (FunctionShell &fn : functions) {
                if (fn.import) {
                    // skip imported functions
                    continue;
                }

                fn.locals = fn.type.params;

                auto function_length = safe_read_leb128<uint32_t>(iter);

                auto start = safe_byte_iterator(
                    iter.get_with_at_least(function_length), function_length);

                auto n_local_decls = safe_read_leb128<uint32_t>(iter);
                while (n_local_decls--) {
                    auto n_locals = safe_read_leb128<uint32_t>(iter);
                    auto type = *iter++;
                    if (!is_valtype(type)) {
                        error<validation_error>("invalid local type");
                    }
                    while (n_locals--) {
                        fn.locals.push_back(static_cast<valtype>(type));
                        if (fn.locals.size() > MAX_LOCALS) {
                            error<malformed_error>("too many locals");
                        }
                    }
                }
                auto body_length = function_length - (iter - start);
                fn.start = iter.get_with_at_least(body_length);

                auto fn_iter = iter;
#ifdef WASM_DEBUG
                std::cerr << "validating function " << &fn - functions.data()
                          << " at " << fn_iter - bytes.get() << std::endl;
#endif
                validate(fn_iter, fn);
                if (fn_iter[-1] != static_cast<uint8_t>(Instruction::end)) {
                    error<malformed_error>("END opcode expected");
                }
                if (fn_iter - start != function_length) {
                    error<malformed_error>("section size mismatch");
                }
                iter += fn_iter - iter;
            }
        },
        [&] {
            if (functions.size() != n_fn_imports) {
                error<malformed_error>(
                    "function and code section have inconsistent lengths");
            }
        });

    skip_custom_section();

    // data section
    section(
        11,
        [&] {
            auto section_n_data = safe_read_leb128<uint32_t>(iter);
            if (has_data_count && n_data != section_n_data) {
                error<malformed_error>("data count and data section have "
                                       "inconsistent lengths");
            }

            for (uint32_t i = 0; i < section_n_data; i++) {
                if (iter.empty()) {
                    error<malformed_error>(
                        "unexpected end of section or function");
                }

                auto segment_flag = safe_read_leb128<uint32_t>(iter);
                if (segment_flag & ~0b11) {
                    error<validation_error>("invalid data segment flag");
                }

                auto memidx =
                    segment_flag & 0b10 ? safe_read_leb128<uint32_t>(iter) : 0;

                if (memidx != 0) {
                    error<validation_error>("unknown memory");
                }

                if (segment_flag & 1) {
                    // passive segment

                    auto data_length = safe_read_leb128<uint32_t>(iter);
                    if (!iter.has_n_left(data_length)) {
                        error<malformed_error>(
                            "unexpected end of section or function");
                    }
                    auto data = std::span<uint8_t>(
                        iter.get_with_at_least(data_length), data_length);
                    iter += data_length;

                    data_segments.emplace_back(Segment{memidx, data, nullptr});
                } else {
                    // active segment
                    if (!memory.exists) {
                        error<validation_error>("unknown memory 0");
                    }

                    auto initializer = iter.unsafe_ptr();
                    validate_const(iter, valtype::i32);
                    auto data_length = safe_read_leb128<uint32_t>(iter);
                    if (!iter.has_n_left(data_length)) {
                        error<malformed_error>(
                            "unexpected end of section or function");
                    }

                    auto data = std::span<uint8_t>(
                        iter.get_with_at_least(data_length), data_length);
                    iter += data_length;

                    // todo: this has to be instantiated
                    data_segments.emplace_back(
                        Segment{memidx, data, initializer});
                }
            }
        },
        [&] {
            if (has_data_count && n_data != 0) {
                error<malformed_error>("data count and data section have "
                                       "inconsistent lengths");
            }
        });

    skip_custom_section();

    if (!iter.empty()) {
        error<malformed_error>("unexpected content after last section");
    }
}

static inline void ensure(bool condition, const char *msg) {
    if (!condition) [[unlikely]] {
        error<validation_error>(msg);
    }
}

class WasmStack {
    bool polymorphized = false;
    valtype buffer_start[65536];
    valtype *buffer;

    auto rbegin() const { return std::reverse_iterator(buffer); }
    auto rend() const {
        return std::reverse_iterator(const_cast<valtype *>(buffer_start));
    }

    template <typename T> auto find_diverging(const T &expected) {
        auto ebegin = expected.rbegin();
        auto abegin = rbegin();

        for (; ebegin != expected.rend(); ++abegin, ++ebegin)
            if (*abegin != *ebegin && *abegin != valtype::any)
                break;

        return abegin;
    }

  public:
#ifdef WASM_DEBUG
    auto begin() { return buffer_start; }
    auto end() { return buffer; }
    auto size() { return std::distance(begin(), end()); }
#endif

    WasmStack() : buffer(buffer_start) {
        std::fill_n(buffer, 1024, valtype::null);
        buffer += 1024;
    }

    template <typename T> bool check(const T &expected) {
        auto diverge = find_diverging(expected);
        if (static_cast<size_t>(std::distance(rbegin(), diverge)) ==
            expected.size())
            return true;
        return polymorphized && *diverge == valtype::null;
    }

    template <typename T> bool operator==(const T &rhs) {
        auto diverge = find_diverging(rhs);
        if (*diverge != valtype::null)
            return false;
        if (static_cast<size_t>(std::distance(rbegin(), diverge)) == rhs.size())
            return true;
        return polymorphized;
    }

    bool polymorphism() { return polymorphized; }
    void set_polymorphism(bool p) { polymorphized = p; }

    void unpolymorphize() { set_polymorphism(false); }

    void polymorphize() {
        set_polymorphism(true);

        buffer = std::find(rbegin(), rend(), valtype::null).base();
    }

    void push(valtype ty) { push(std::array{ty}); }
    template <typename T> void push(const T &values) {
        std::copy(values.begin(), values.end(), buffer);
        buffer += values.size();
    }
    void pop(valtype expected_ty) { pop(std::array{expected_ty}); }
    template <typename T> void pop(const T &expected) {
        ensure(check(expected), "type mismatch");

        auto diverge = find_diverging(expected);
        buffer -= std::distance(rbegin(), diverge);
    }

    bool empty() const { return !polymorphized && *rbegin() == valtype::null; }

    bool can_be_anything() const {
        return polymorphized && *rbegin() == valtype::null;
    }

    valtype back() const {
        if (auto b = *rbegin(); b != valtype::null)
            return b;
        if (polymorphized) {
            return valtype::any;
        } else {
            error<validation_error>("type mismatch");
        }
    }

    template <size_t pc, size_t rc>
    void apply(std::array<valtype, pc> params,
               std::array<valtype, rc> results) {
        pop(params);
        push(results);
    }

    void apply(const Signature &signature) {
        pop(signature.params);
        push(signature.results);
    };

    void enter_flow(const std::vector<valtype> &expected) {
        pop(expected);
        push(valtype::null);
        push(expected);
    };

    void check_br(std::vector<ControlFlow> &control_stack, uint32_t depth) {
        ensure(depth < control_stack.size(), "unknown label");
        auto &target = control_stack[control_stack.size() - depth - 1];
        pop(target.expected);
        push(target.expected);
    };
};

#define LOAD(type, stacktype)                                                  \
    {                                                                          \
        auto a = safe_read_leb128<uint32_t>(iter);                             \
        ensure(mod.memory.exists, "unknown memory");                           \
        if (a >= 32) {                                                         \
            error<malformed_error>("malformed memop flags");                   \
        }                                                                      \
        auto align = 1ull << a;                                                \
        ensure(align <= sizeof(type),                                          \
               "alignment must not be larger than natural");                   \
        /* auto offset = */ safe_read_leb128<uint32_t>(iter);                  \
        stack.apply(std::array{valtype::i32}, std::array{stacktype});          \
        nextop();                                                              \
    }

#define STORE(type, stacktype)                                                 \
    {                                                                          \
        auto a = safe_read_leb128<uint32_t>(iter);                             \
        if ((1 << 6) & a) {                                                    \
            a -= 1 << 6;                                                       \
            /* todo: test multi memory proposal */                             \
            a = safe_read_leb128<uint32_t>(iter);                              \
        } else {                                                               \
            ensure(mod.memory.exists, "unknown memory");                       \
        }                                                                      \
        auto align = 1ull << a;                                                \
        ensure(align <= sizeof(type),                                          \
               "alignment must not be larger than natural");                   \
        /* auto offset = */ safe_read_leb128<uint32_t>(iter);                  \
        stack.apply(std::array{valtype::i32, stacktype},                       \
                    std::array<valtype, 0>());                                 \
        nextop();                                                              \
    }

#define HANDLER(name)                                                          \
    void validate_##name(Module &mod, safe_byte_iterator &iter,                \
                         FunctionShell &fn, WasmStack &stack,                  \
                         std::vector<ControlFlow> &control_stack)

#define V(name, _, byte) HANDLER(name);
FOREACH_INSTRUCTION(V)
#undef V

#ifdef WASM_DEBUG
#define nextop()                                                               \
    do {                                                                       \
        auto byte = *iter++;                                                   \
        std::cerr << "reading instruction " << instructions[byte].c_str()      \
                  << " at " << iter - mod.bytes.get() << std::endl;            \
        std::cerr << "control stack size: " << control_stack.size()            \
                  << std::endl;                                                \
        std::cerr << "control stack: ";                                        \
        for (auto &target : control_stack) {                                   \
            std::cerr << target.expected.size() << " ";                        \
        }                                                                      \
        std::cerr << std::endl;                                                \
        std::cerr << "stack size: " << stack.size() << std::endl;              \
        std::cerr << "stack: ";                                                \
        for (auto &ty : stack) {                                               \
            std::cerr << valtype_names[static_cast<uint8_t>(ty)].c_str()       \
                      << " ";                                                  \
        }                                                                      \
        std::cerr << std::endl;                                                \
        std::cerr << std::endl;                                                \
        [[clang::musttail]] return funcs[byte](mod, iter, fn, stack,           \
                                               control_stack);                 \
    } while (0)
#else
#define nextop()                                                               \
    do {                                                                       \
        [[clang::musttail]] return funcs[*iter++](mod, iter, fn, stack,        \
                                                  control_stack);              \
    } while (0)
#endif

HANDLER(missing);

consteval std::array<ValidationHandler *, 256> make_funcs() {
    std::array<ValidationHandler *, 256> funcs{};
    funcs.fill(&validate_missing);

#define V(name, _, byte) funcs[byte] = &validate_##name;
    FOREACH_INSTRUCTION(V)
#undef V

    return funcs;
}

static auto funcs = make_funcs();

HANDLER(missing) {
    error<malformed_error>("unknown instruction");
    nextop();
}

HANDLER(unreachable) {
    stack.polymorphize();
    nextop();
}
HANDLER(nop) { nextop(); }
HANDLER(block) {
    auto &signature = Signature::read_blocktype(mod.types, iter);
    auto block_start = iter.unsafe_ptr();

    stack.enter_flow(signature.params);
    control_stack.emplace_back(ControlFlow(signature.results, signature,
                                           stack.polymorphism(),
                                           Block(block_start)));
    stack.unpolymorphize();
    nextop();
}
HANDLER(loop) {
    auto &signature = Signature::read_blocktype(mod.types, iter);

    stack.enter_flow(signature.params);
    control_stack.emplace_back(
        ControlFlow(signature.params, signature, stack.polymorphism(), Loop()));
    stack.unpolymorphize();
    nextop();
}
HANDLER(if_) {
    auto &signature = Signature::read_blocktype(mod.types, iter);
    auto if_start = iter.unsafe_ptr();

    stack.pop(valtype::i32);
    stack.enter_flow(signature.params);
    control_stack.emplace_back(ControlFlow(signature.results, signature,
                                           stack.polymorphism(), If(if_start)));
    stack.unpolymorphize();
    nextop();
}
HANDLER(else_) {
    auto &[_, sig, __, construct] = control_stack.back();
    ensure(std::holds_alternative<If>(construct), "else must close an if");
    ensure(stack == sig.results, "type mismatch");

    stack.pop(sig.results);
    stack.push(sig.params);

    auto &if_ = std::get<If>(construct);
    control_stack.back().construct = IfElse(if_.if_start, iter.unsafe_ptr());
    stack.unpolymorphize();
    nextop();
}
HANDLER(end) {
    if (control_stack.size() == 1) {
        ensure(stack == fn.type.results, "type mismatch stack vs. results");
        return;
    }

    auto &[_, sig, polymorphism, construct] = control_stack.back();

    ensure(stack == sig.results, "type mismatch stack vs. results");

    if (std::holds_alternative<Block>(construct)) {
        auto &[block_start] = std::get<Block>(construct);
        mod.block_ends[block_start] = iter.unsafe_ptr();
    } else if (std::holds_alternative<Loop>(construct)) {
        // do nothing
    } else if (std::holds_alternative<If>(construct)) {
        ensure(sig.params == sig.results, "type mismatch params vs. results");
        auto &[if_start] = std::get<If>(construct);
        mod.if_jumps[if_start] = {iter.unsafe_ptr() - 1, iter.unsafe_ptr()};
    } else if (std::holds_alternative<IfElse>(construct)) {
        auto &[if_start, else_start] = std::get<IfElse>(construct);
        mod.if_jumps[if_start] = {else_start, iter.unsafe_ptr()};
    }
    stack.pop(sig.results);
    stack.pop(valtype::null);

    stack.set_polymorphism(polymorphism);
    stack.push(sig.results);

    control_stack.pop_back();
    nextop();
}
HANDLER(br) {
    stack.check_br(control_stack, safe_read_leb128<uint32_t>(iter));
    stack.polymorphize();
    nextop();
}
HANDLER(br_if) {
    stack.pop(valtype::i32);
    auto depth = safe_read_leb128<uint32_t>(iter);
    stack.check_br(control_stack, depth);
    nextop();
}
HANDLER(br_table) {
    stack.pop(valtype::i32);
    auto n_targets = safe_read_leb128<uint32_t>(iter);

    auto targets = (uint32_t *)alloca(sizeof(uint32_t) * (n_targets + 1));
    for (uint32_t i = 0; i <= n_targets; ++i) {
        auto target = safe_read_leb128<uint32_t>(iter);
        ensure(target < control_stack.size(), "unknown label");
        targets[i] = target;
    }
    auto base = control_stack.size() - 1;
    auto &default_target = control_stack[base - targets[n_targets]].expected;
    for (uint32_t i = 0; i <= n_targets; ++i) {
        auto &target = control_stack[base - targets[i]].expected;
        if (stack.can_be_anything()) {
            ensure(stack.check(target), "type mismatch");
            ensure(default_target.size() == target.size(), "type mismatch");
        } else {
            stack.check_br(control_stack, targets[i]);
            ensure(default_target == target, "type mismatch");
        }
    }
    stack.polymorphize();
    nextop();
}
HANDLER(return_) {
    stack.check_br(control_stack, control_stack.size() - 1);
    stack.polymorphize();
    nextop();
}
HANDLER(call) {
    auto fn_idx = safe_read_leb128<uint32_t>(iter);
    ensure(fn_idx < mod.functions.size(), "unknown function");

    auto &func = mod.functions[fn_idx];
    stack.apply(func.type);
    nextop();
}
HANDLER(call_indirect) {
    stack.pop(valtype::i32);

    auto type_idx = safe_read_leb128<uint32_t>(iter);
    ensure(type_idx < mod.types.size(), "unknown type");

    auto table_idx = safe_read_leb128<uint32_t>(iter);
    ensure(table_idx < mod.tables.size(), "unknown table");
    ensure(mod.tables[table_idx].type == valtype::funcref, "type mismatch");

    stack.apply(mod.types[type_idx]);
    nextop();
}
HANDLER(drop) {
    stack.pop(stack.back());
    nextop();
}
HANDLER(select) {
    // first pop the condition
    stack.pop(valtype::i32);

    auto ty = stack.back();
    ensure(ty == valtype::any || is_numtype(ty), "type mismatch");

    // then apply the dynamic type
    stack.apply(std::array{ty, ty}, std::array{ty});
    nextop();
}
HANDLER(select_t) {
    auto n_results = safe_read_leb128<uint32_t>(iter);
    ensure(n_results == 1, "invalid result arity");
    auto maybe_valtype = *iter++;
    ensure(is_valtype(maybe_valtype), "invalid result type");

    // first pop the condition
    stack.pop(valtype::i32);
    auto ty = stack.back();
    // then apply the dynamic type
    stack.apply(std::array{ty, ty}, std::array{ty});
    nextop();
}
HANDLER(localget) {
    auto local_idx = safe_read_leb128<uint32_t>(iter);
    ensure(local_idx < fn.locals.size(), "unknown local");
    auto local_ty = fn.locals[local_idx];
    stack.apply(std::array<valtype, 0>(), std::array{local_ty});
    nextop();
}
HANDLER(localset) {
    auto local_idx = safe_read_leb128<uint32_t>(iter);
    ensure(local_idx < fn.locals.size(), "unknown local");
    auto local_ty = fn.locals[local_idx];
    stack.apply(std::array{local_ty}, std::array<valtype, 0>());
    nextop();
}
HANDLER(localtee) {
    auto local_idx = safe_read_leb128<uint32_t>(iter);
    ensure(local_idx < fn.locals.size(), "unknown local");
    auto local_ty = fn.locals[local_idx];
    stack.apply(std::array{local_ty}, std::array{local_ty});
    nextop();
}
HANDLER(tableget) {
    auto table_idx = safe_read_leb128<uint32_t>(iter);
    ensure(table_idx < mod.tables.size(), "unknown table");
    auto table_ty = mod.tables[table_idx].type;
    stack.apply(std::array{valtype::i32}, std::array{table_ty});
    nextop();
}
HANDLER(tableset) {
    auto table_idx = safe_read_leb128<uint32_t>(iter);
    ensure(table_idx < mod.tables.size(), "unknown table");
    auto table_ty = mod.tables[table_idx].type;
    stack.apply(std::array{valtype::i32, table_ty}, std::array<valtype, 0>());
    nextop();
}
HANDLER(globalget) {
    auto global_idx = safe_read_leb128<uint32_t>(iter);
    ensure(global_idx < mod.globals.size(), "unknown global");
    auto global_ty = mod.globals[global_idx].type;
    stack.apply(std::array<valtype, 0>(), std::array{global_ty});
    nextop();
}
HANDLER(globalset) {
    auto global_idx = safe_read_leb128<uint32_t>(iter);
    ensure(global_idx < mod.globals.size(), "unknown global");
    ensure(mod.globals[global_idx].mutability == mut::var,
           "global is immutable");
    auto global_ty = mod.globals[global_idx].type;
    stack.apply(std::array{global_ty}, std::array<valtype, 0>());
    nextop();
}
HANDLER(memorysize) {
    if (*iter++ != 0)
        error<malformed_error>("zero byte expected");
    ensure(mod.memory.exists, "unknown memory");
    stack.apply(std::array<valtype, 0>(), std::array{valtype::i32});
    nextop();
}
HANDLER(memorygrow) {
    if (*iter++ != 0)
        error<malformed_error>("zero byte expected");
    ensure(mod.memory.exists, "unknown memory");
    stack.apply(std::array{valtype::i32}, std::array{valtype::i32});
    nextop();
}
HANDLER(i32const) {
    safe_read_sleb128<uint32_t>(iter);
    stack.apply(std::array<valtype, 0>(), std::array{valtype::i32});
    nextop();
}
HANDLER(i64const) {
    safe_read_sleb128<uint64_t>(iter);
    stack.apply(std::array<valtype, 0>(), std::array{valtype::i64});
    nextop();
}
HANDLER(f32const) {
    iter += sizeof(float);
    stack.apply(std::array<valtype, 0>(), std::array{valtype::f32});
    nextop();
}
HANDLER(f64const) {
    iter += sizeof(double);
    stack.apply(std::array<valtype, 0>(), std::array{valtype::f64});
    nextop();
}
// clang-format off
HANDLER(i32load) {     LOAD(uint32_t,  valtype::i32); }
HANDLER(i64load) {     LOAD(uint64_t,  valtype::i64); }
HANDLER(f32load) {     LOAD(float,     valtype::f32); }
HANDLER(f64load) {     LOAD(double,    valtype::f64); }
HANDLER(i32load8_s) {  LOAD(int8_t,    valtype::i32); }
HANDLER(i32load8_u) {  LOAD(uint8_t,   valtype::i32); }
HANDLER(i32load16_s) { LOAD(int16_t,   valtype::i32); }
HANDLER(i32load16_u) { LOAD(uint16_t,  valtype::i32); }
HANDLER(i64load8_s) {  LOAD(int8_t,    valtype::i64); }
HANDLER(i64load8_u) {  LOAD(uint8_t,   valtype::i64); }
HANDLER(i64load16_s) { LOAD(int16_t,   valtype::i64); }
HANDLER(i64load16_u) { LOAD(uint16_t,  valtype::i64); }
HANDLER(i64load32_s) { LOAD(int32_t,   valtype::i64); }
HANDLER(i64load32_u) { LOAD(uint32_t,  valtype::i64); }
HANDLER(i32store) {    STORE(uint32_t, valtype::i32); }
HANDLER(i64store) {    STORE(uint64_t, valtype::i64); }
HANDLER(f32store) {    STORE(float,    valtype::f32); }
HANDLER(f64store) {    STORE(double,   valtype::f64); }
HANDLER(i32store8) {   STORE(uint8_t,  valtype::i32); }
HANDLER(i32store16) {  STORE(uint16_t, valtype::i32); }
HANDLER(i64store8) {   STORE(uint8_t,  valtype::i64); }
HANDLER(i64store16) {  STORE(uint16_t, valtype::i64); }
HANDLER(i64store32) {  STORE(uint32_t, valtype::i64); }
HANDLER(i32eqz) {      stack.apply(std::array{valtype::i32              }, std::array{valtype::i32}); nextop(); }
HANDLER(i64eqz) {      stack.apply(std::array{valtype::i64              }, std::array{valtype::i32}); nextop(); }
HANDLER(i32eq) {       stack.apply(std::array{valtype::i32, valtype::i32}, std::array{valtype::i32}); nextop(); }
HANDLER(i64eq) {       stack.apply(std::array{valtype::i64, valtype::i64}, std::array{valtype::i32}); nextop(); }
HANDLER(i32ne) {       stack.apply(std::array{valtype::i32, valtype::i32}, std::array{valtype::i32}); nextop(); }
HANDLER(i64ne) {       stack.apply(std::array{valtype::i64, valtype::i64}, std::array{valtype::i32}); nextop(); }
HANDLER(i32lt_s) {     stack.apply(std::array{valtype::i32, valtype::i32}, std::array{valtype::i32}); nextop(); }
HANDLER(i64lt_s) {     stack.apply(std::array{valtype::i64, valtype::i64}, std::array{valtype::i32}); nextop(); }
HANDLER(i32lt_u) {     stack.apply(std::array{valtype::i32, valtype::i32}, std::array{valtype::i32}); nextop(); }
HANDLER(i64lt_u) {     stack.apply(std::array{valtype::i64, valtype::i64}, std::array{valtype::i32}); nextop(); }
HANDLER(i32gt_s) {     stack.apply(std::array{valtype::i32, valtype::i32}, std::array{valtype::i32}); nextop(); }
HANDLER(i64gt_s) {     stack.apply(std::array{valtype::i64, valtype::i64}, std::array{valtype::i32}); nextop(); }
HANDLER(i32gt_u) {     stack.apply(std::array{valtype::i32, valtype::i32}, std::array{valtype::i32}); nextop(); }
HANDLER(i64gt_u) {     stack.apply(std::array{valtype::i64, valtype::i64}, std::array{valtype::i32}); nextop(); }
HANDLER(i32le_s) {     stack.apply(std::array{valtype::i32, valtype::i32}, std::array{valtype::i32}); nextop(); }
HANDLER(i64le_s) {     stack.apply(std::array{valtype::i64, valtype::i64}, std::array{valtype::i32}); nextop(); }
HANDLER(i32le_u) {     stack.apply(std::array{valtype::i32, valtype::i32}, std::array{valtype::i32}); nextop(); }
HANDLER(i64le_u) {     stack.apply(std::array{valtype::i64, valtype::i64}, std::array{valtype::i32}); nextop(); }
HANDLER(i32ge_s) {     stack.apply(std::array{valtype::i32, valtype::i32}, std::array{valtype::i32}); nextop(); }
HANDLER(i64ge_s) {     stack.apply(std::array{valtype::i64, valtype::i64}, std::array{valtype::i32}); nextop(); }
HANDLER(i32ge_u) {     stack.apply(std::array{valtype::i32, valtype::i32}, std::array{valtype::i32}); nextop(); }
HANDLER(i64ge_u) {     stack.apply(std::array{valtype::i64, valtype::i64}, std::array{valtype::i32}); nextop(); }
HANDLER(f32eq) {       stack.apply(std::array{valtype::f32, valtype::f32}, std::array{valtype::i32}); nextop(); }
HANDLER(f64eq) {       stack.apply(std::array{valtype::f64, valtype::f64}, std::array{valtype::i32}); nextop(); }
HANDLER(f32ne) {       stack.apply(std::array{valtype::f32, valtype::f32}, std::array{valtype::i32}); nextop(); }
HANDLER(f64ne) {       stack.apply(std::array{valtype::f64, valtype::f64}, std::array{valtype::i32}); nextop(); }
HANDLER(f32lt) {       stack.apply(std::array{valtype::f32, valtype::f32}, std::array{valtype::i32}); nextop(); }
HANDLER(f64lt) {       stack.apply(std::array{valtype::f64, valtype::f64}, std::array{valtype::i32}); nextop(); }
HANDLER(f32gt) {       stack.apply(std::array{valtype::f32, valtype::f32}, std::array{valtype::i32}); nextop(); }
HANDLER(f64gt) {       stack.apply(std::array{valtype::f64, valtype::f64}, std::array{valtype::i32}); nextop(); }
HANDLER(f32le) {       stack.apply(std::array{valtype::f32, valtype::f32}, std::array{valtype::i32}); nextop(); }
HANDLER(f64le) {       stack.apply(std::array{valtype::f64, valtype::f64}, std::array{valtype::i32}); nextop(); }
HANDLER(f32ge) {       stack.apply(std::array{valtype::f32, valtype::f32}, std::array{valtype::i32}); nextop(); }
HANDLER(f64ge) {       stack.apply(std::array{valtype::f64, valtype::f64}, std::array{valtype::i32}); nextop(); }
HANDLER(i32clz) {      stack.apply(std::array{valtype::i32              }, std::array{valtype::i32}); nextop(); }
HANDLER(i64clz) {      stack.apply(std::array{valtype::i64              }, std::array{valtype::i64}); nextop(); }
HANDLER(i32ctz) {      stack.apply(std::array{valtype::i32              }, std::array{valtype::i32}); nextop(); }
HANDLER(i64ctz) {      stack.apply(std::array{valtype::i64              }, std::array{valtype::i64}); nextop(); }
HANDLER(i32popcnt) {   stack.apply(std::array{valtype::i32              }, std::array{valtype::i32}); nextop(); }
HANDLER(i64popcnt) {   stack.apply(std::array{valtype::i64              }, std::array{valtype::i64}); nextop(); }
HANDLER(i32add) {      stack.apply(std::array{valtype::i32, valtype::i32}, std::array{valtype::i32}); nextop(); }
HANDLER(i64add) {      stack.apply(std::array{valtype::i64, valtype::i64}, std::array{valtype::i64}); nextop(); }
HANDLER(i32sub) {      stack.apply(std::array{valtype::i32, valtype::i32}, std::array{valtype::i32}); nextop(); }
HANDLER(i64sub) {      stack.apply(std::array{valtype::i64, valtype::i64}, std::array{valtype::i64}); nextop(); }
HANDLER(i32mul) {      stack.apply(std::array{valtype::i32, valtype::i32}, std::array{valtype::i32}); nextop(); }
HANDLER(i64mul) {      stack.apply(std::array{valtype::i64, valtype::i64}, std::array{valtype::i64}); nextop(); }
HANDLER(i32div_s) {    stack.apply(std::array{valtype::i32, valtype::i32}, std::array{valtype::i32}); nextop(); }
HANDLER(i64div_s) {    stack.apply(std::array{valtype::i64, valtype::i64}, std::array{valtype::i64}); nextop(); }
HANDLER(i32div_u) {    stack.apply(std::array{valtype::i32, valtype::i32}, std::array{valtype::i32}); nextop(); }
HANDLER(i64div_u) {    stack.apply(std::array{valtype::i64, valtype::i64}, std::array{valtype::i64}); nextop(); }
HANDLER(i32rem_s) {    stack.apply(std::array{valtype::i32, valtype::i32}, std::array{valtype::i32}); nextop(); }
HANDLER(i64rem_s) {    stack.apply(std::array{valtype::i64, valtype::i64}, std::array{valtype::i64}); nextop(); }
HANDLER(i32rem_u) {    stack.apply(std::array{valtype::i32, valtype::i32}, std::array{valtype::i32}); nextop(); }
HANDLER(i64rem_u) {    stack.apply(std::array{valtype::i64, valtype::i64}, std::array{valtype::i64}); nextop(); }
HANDLER(i32and) {      stack.apply(std::array{valtype::i32, valtype::i32}, std::array{valtype::i32}); nextop(); }
HANDLER(i64and) {      stack.apply(std::array{valtype::i64, valtype::i64}, std::array{valtype::i64}); nextop(); }
HANDLER(i32or) {       stack.apply(std::array{valtype::i32, valtype::i32}, std::array{valtype::i32}); nextop(); }
HANDLER(i64or) {       stack.apply(std::array{valtype::i64, valtype::i64}, std::array{valtype::i64}); nextop(); }
HANDLER(i32xor) {      stack.apply(std::array{valtype::i32, valtype::i32}, std::array{valtype::i32}); nextop(); }
HANDLER(i64xor) {      stack.apply(std::array{valtype::i64, valtype::i64}, std::array{valtype::i64}); nextop(); }
HANDLER(i32shl) {      stack.apply(std::array{valtype::i32, valtype::i32}, std::array{valtype::i32}); nextop(); }
HANDLER(i64shl) {      stack.apply(std::array{valtype::i64, valtype::i64}, std::array{valtype::i64}); nextop(); }
HANDLER(i32shr_s) {    stack.apply(std::array{valtype::i32, valtype::i32}, std::array{valtype::i32}); nextop(); }
HANDLER(i64shr_s) {    stack.apply(std::array{valtype::i64, valtype::i64}, std::array{valtype::i64}); nextop(); }
HANDLER(i32shr_u) {    stack.apply(std::array{valtype::i32, valtype::i32}, std::array{valtype::i32}); nextop(); }
HANDLER(i64shr_u) {    stack.apply(std::array{valtype::i64, valtype::i64}, std::array{valtype::i64}); nextop(); }
HANDLER(i32rotl) {     stack.apply(std::array{valtype::i32, valtype::i32}, std::array{valtype::i32}); nextop(); }
HANDLER(i64rotl) {     stack.apply(std::array{valtype::i64, valtype::i64}, std::array{valtype::i64}); nextop(); }
HANDLER(i32rotr) {     stack.apply(std::array{valtype::i32, valtype::i32}, std::array{valtype::i32}); nextop(); }
HANDLER(i64rotr) {     stack.apply(std::array{valtype::i64, valtype::i64}, std::array{valtype::i64}); nextop(); }
HANDLER(f32abs) {      stack.apply(std::array{valtype::f32              }, std::array{valtype::f32}); nextop(); }
HANDLER(f64abs) {      stack.apply(std::array{valtype::f64              }, std::array{valtype::f64}); nextop(); }
HANDLER(f32neg) {      stack.apply(std::array{valtype::f32              }, std::array{valtype::f32}); nextop(); }
HANDLER(f64neg) {      stack.apply(std::array{valtype::f64              }, std::array{valtype::f64}); nextop(); }
HANDLER(f32ceil) {     stack.apply(std::array{valtype::f32              }, std::array{valtype::f32}); nextop(); }
HANDLER(f64ceil) {     stack.apply(std::array{valtype::f64              }, std::array{valtype::f64}); nextop(); }
HANDLER(f32floor) {    stack.apply(std::array{valtype::f32              }, std::array{valtype::f32}); nextop(); }
HANDLER(f64floor) {    stack.apply(std::array{valtype::f64              }, std::array{valtype::f64}); nextop(); }
HANDLER(f32trunc) {    stack.apply(std::array{valtype::f32              }, std::array{valtype::f32}); nextop(); }
HANDLER(f64trunc) {    stack.apply(std::array{valtype::f64              }, std::array{valtype::f64}); nextop(); }
HANDLER(f32nearest) {  stack.apply(std::array{valtype::f32              }, std::array{valtype::f32}); nextop(); }
HANDLER(f64nearest) {  stack.apply(std::array{valtype::f64              }, std::array{valtype::f64}); nextop(); }
HANDLER(f32sqrt) {     stack.apply(std::array{valtype::f32              }, std::array{valtype::f32}); nextop(); }
HANDLER(f64sqrt) {     stack.apply(std::array{valtype::f64              }, std::array{valtype::f64}); nextop(); }
HANDLER(f32add) {      stack.apply(std::array{valtype::f32, valtype::f32}, std::array{valtype::f32}); nextop(); }
HANDLER(f64add) {      stack.apply(std::array{valtype::f64, valtype::f64}, std::array{valtype::f64}); nextop(); }
HANDLER(f32sub) {      stack.apply(std::array{valtype::f32, valtype::f32}, std::array{valtype::f32}); nextop(); }
HANDLER(f64sub) {      stack.apply(std::array{valtype::f64, valtype::f64}, std::array{valtype::f64}); nextop(); }
HANDLER(f32mul) {      stack.apply(std::array{valtype::f32, valtype::f32}, std::array{valtype::f32}); nextop(); }
HANDLER(f64mul) {      stack.apply(std::array{valtype::f64, valtype::f64}, std::array{valtype::f64}); nextop(); }
HANDLER(f32div) {      stack.apply(std::array{valtype::f32, valtype::f32}, std::array{valtype::f32}); nextop(); }
HANDLER(f64div) {      stack.apply(std::array{valtype::f64, valtype::f64}, std::array{valtype::f64}); nextop(); }
HANDLER(f32min) {      stack.apply(std::array{valtype::f32, valtype::f32}, std::array{valtype::f32}); nextop(); }
HANDLER(f64min) {      stack.apply(std::array{valtype::f64, valtype::f64}, std::array{valtype::f64}); nextop(); }
HANDLER(f32max) {      stack.apply(std::array{valtype::f32, valtype::f32}, std::array{valtype::f32}); nextop(); }
HANDLER(f64max) {      stack.apply(std::array{valtype::f64, valtype::f64}, std::array{valtype::f64}); nextop(); }
HANDLER(f32copysign) { stack.apply(std::array{valtype::f32, valtype::f32}, std::array{valtype::f32}); nextop(); }
HANDLER(f64copysign) { stack.apply(std::array{valtype::f64, valtype::f64}, std::array{valtype::f64}); nextop(); }
HANDLER(i32wrap_i64) {      stack.apply(std::array{valtype::i64}, std::array{valtype::i32}); nextop(); }
HANDLER(i64extend_i32_s) {  stack.apply(std::array{valtype::i32}, std::array{valtype::i64}); nextop(); }
HANDLER(i64extend_i32_u) {  stack.apply(std::array{valtype::i32}, std::array{valtype::i64}); nextop(); }
HANDLER(i32trunc_f32_s) {   stack.apply(std::array{valtype::f32}, std::array{valtype::i32}); nextop(); }
HANDLER(i64trunc_f32_s) {   stack.apply(std::array{valtype::f32}, std::array{valtype::i64}); nextop(); }
HANDLER(i32trunc_f32_u) {   stack.apply(std::array{valtype::f32}, std::array{valtype::i32}); nextop(); }
HANDLER(i64trunc_f32_u) {   stack.apply(std::array{valtype::f32}, std::array{valtype::i64}); nextop(); }
HANDLER(i32trunc_f64_s) {   stack.apply(std::array{valtype::f64}, std::array{valtype::i32}); nextop(); }
HANDLER(i64trunc_f64_s) {   stack.apply(std::array{valtype::f64}, std::array{valtype::i64}); nextop(); }
HANDLER(i32trunc_f64_u) {   stack.apply(std::array{valtype::f64}, std::array{valtype::i32}); nextop(); }
HANDLER(i64trunc_f64_u) {   stack.apply(std::array{valtype::f64}, std::array{valtype::i64}); nextop(); }
HANDLER(f32convert_i32_s) { stack.apply(std::array{valtype::i32}, std::array{valtype::f32}); nextop(); }
HANDLER(f64convert_i32_s) { stack.apply(std::array{valtype::i32}, std::array{valtype::f64}); nextop(); }
HANDLER(f32convert_i32_u) { stack.apply(std::array{valtype::i32}, std::array{valtype::f32}); nextop(); }
HANDLER(f64convert_i32_u) { stack.apply(std::array{valtype::i32}, std::array{valtype::f64}); nextop(); }
HANDLER(f32convert_i64_s) { stack.apply(std::array{valtype::i64}, std::array{valtype::f32}); nextop(); }
HANDLER(f64convert_i64_s) { stack.apply(std::array{valtype::i64}, std::array{valtype::f64}); nextop(); }
HANDLER(f32convert_i64_u) { stack.apply(std::array{valtype::i64}, std::array{valtype::f32}); nextop(); }
HANDLER(f64convert_i64_u) { stack.apply(std::array{valtype::i64}, std::array{valtype::f64}); nextop(); }
HANDLER(f32demote_f64) {    stack.apply(std::array{valtype::f64}, std::array{valtype::f32}); nextop(); }
HANDLER(f64promote_f32) {   stack.apply(std::array{valtype::f32}, std::array{valtype::f64}); nextop(); }
HANDLER(i32reinterpret_f32) { stack.apply(std::array{valtype::f32}, std::array{valtype::i32}); nextop(); }
HANDLER(f32reinterpret_i32) { stack.apply(std::array{valtype::i32}, std::array{valtype::f32}); nextop(); }
HANDLER(i64reinterpret_f64) { stack.apply(std::array{valtype::f64}, std::array{valtype::i64}); nextop(); }
HANDLER(f64reinterpret_i64) { stack.apply(std::array{valtype::i64}, std::array{valtype::f64}); nextop(); }
HANDLER(i32extend8_s) {  stack.apply(std::array{valtype::i32}, std::array{valtype::i32}); nextop(); }
HANDLER(i32extend16_s) { stack.apply(std::array{valtype::i32}, std::array{valtype::i32}); nextop(); }
HANDLER(i64extend8_s) {  stack.apply(std::array{valtype::i64}, std::array{valtype::i64}); nextop(); }
HANDLER(i64extend16_s) { stack.apply(std::array{valtype::i64}, std::array{valtype::i64}); nextop(); }
HANDLER(i64extend32_s) { stack.apply(std::array{valtype::i64}, std::array{valtype::i64}); nextop(); }
// clang-format on
HANDLER(ref_null) {
    auto type_idx = safe_read_leb128<uint32_t>(iter);
    ensure(is_reftype(type_idx), "type mismatch");
    stack.apply(std::array<valtype, 0>(),
                std::array{static_cast<valtype>(type_idx)});
    nextop();
}
HANDLER(ref_is_null) {
    auto peek = stack.back();
    ensure(peek == valtype::any || is_reftype(peek), "type mismatch");
    stack.apply(std::array{peek}, std::array{valtype::i32});
    nextop();
}
HANDLER(ref_func) {
    auto func_idx = safe_read_leb128<uint32_t>(iter);
    ensure(func_idx < mod.functions.size(), "invalid function index");
    ensure(mod.functions[func_idx].is_declared,
           "undeclared function reference");
    stack.apply(std::array<valtype, 0>(), std::array{valtype::funcref});
    nextop();
}
HANDLER(ref_eq) {
    auto peek = stack.back();
    ensure(peek == valtype::any || is_reftype(peek), "type mismatch");
    stack.apply(std::array{peek, peek}, std::array{valtype::i32});
    nextop();
}
HANDLER(i32_trunc_sat_f32_s) {
    stack.apply(std::array{valtype::f32}, std::array{valtype::i32});
    nextop();
}
HANDLER(i32_trunc_sat_f32_u) {
    stack.apply(std::array{valtype::f32}, std::array{valtype::i32});
    nextop();
}
HANDLER(i32_trunc_sat_f64_s) {
    stack.apply(std::array{valtype::f64}, std::array{valtype::i32});
    nextop();
}
HANDLER(i32_trunc_sat_f64_u) {
    stack.apply(std::array{valtype::f64}, std::array{valtype::i32});
    nextop();
}
HANDLER(i64_trunc_sat_f32_s) {
    stack.apply(std::array{valtype::f32}, std::array{valtype::i64});
    nextop();
}
HANDLER(i64_trunc_sat_f32_u) {
    stack.apply(std::array{valtype::f32}, std::array{valtype::i64});
    nextop();
}
HANDLER(i64_trunc_sat_f64_s) {
    stack.apply(std::array{valtype::f64}, std::array{valtype::i64});
    nextop();
}
HANDLER(i64_trunc_sat_f64_u) {
    stack.apply(std::array{valtype::f64}, std::array{valtype::i64});
    nextop();
}
HANDLER(memory_init) {
    auto seg_idx = safe_read_leb128<uint32_t>(iter);
    if (*iter++ != 0)
        error<malformed_error>("zero byte expected");

    ensure(mod.memory.exists, "unknown memory 0");
    if (mod.n_data == std::numeric_limits<uint32_t>::max()) {
        error<malformed_error>("data count section required");
    }
    ensure(seg_idx < mod.n_data, "unknown data segment");

    stack.apply(std::array{valtype::i32, valtype::i32, valtype::i32},
                std::array<valtype, 0>());
    nextop();
}
HANDLER(data_drop) {
    auto seg_idx = safe_read_leb128<uint32_t>(iter);
    if (mod.n_data == std::numeric_limits<uint32_t>::max()) {
        error<malformed_error>("data count section required");
    }
    ensure(seg_idx < mod.n_data, "unknown data segment");
    nextop();
}
HANDLER(memory_copy) {
    if (*iter++ != 0)
        error<malformed_error>("zero byte expected");
    if (*iter++ != 0)
        error<malformed_error>("zero byte expected");
    ensure(mod.memory.exists, "unknown memory 0");

    stack.apply(std::array{valtype::i32, valtype::i32, valtype::i32},
                std::array<valtype, 0>());
    nextop();
}
HANDLER(memory_fill) {
    if (*iter++ != 0)
        error<malformed_error>("zero byte expected");
    ensure(mod.memory.exists, "unknown memory 0");

    stack.apply(std::array{valtype::i32, valtype::i32, valtype::i32},
                std::array<valtype, 0>());
    nextop();
}
HANDLER(table_init) {
    auto seg_idx = safe_read_leb128<uint32_t>(iter);
    auto table_idx = safe_read_leb128<uint32_t>(iter);

    ensure(table_idx < mod.tables.size(), "unknown table");
    ensure(seg_idx < mod.elements.size(), "unknown data segment");
    ensure(mod.tables[table_idx].type == mod.elements[seg_idx].type,
           "type mismatch");

    stack.apply(std::array{valtype::i32, valtype::i32, valtype::i32},
                std::array<valtype, 0>());
    nextop();
}
HANDLER(elem_drop) {
    auto seg_idx = safe_read_leb128<uint32_t>(iter);
    ensure(seg_idx < mod.elements.size(), "unknown elem segment");
    nextop();
}
HANDLER(table_copy) {
    auto src_table_idx = safe_read_leb128<uint32_t>(iter);
    ensure(src_table_idx < mod.tables.size(), "unknown table");
    auto dst_table_idx = safe_read_leb128<uint32_t>(iter);
    ensure(dst_table_idx < mod.tables.size(), "unknown table");
    ensure(mod.tables[src_table_idx].type == mod.tables[dst_table_idx].type,
           "type mismatch");

    stack.apply(std::array{valtype::i32, valtype::i32, valtype::i32},
                std::array<valtype, 0>());
    nextop();
}
HANDLER(table_grow) {
    auto table_idx = safe_read_leb128<uint32_t>(iter);
    ensure(table_idx < mod.tables.size(), "unknown table");

    stack.apply(std::array{mod.tables[table_idx].type, valtype::i32},
                std::array{valtype::i32});
    nextop();
}
HANDLER(table_size) {
    auto table_idx = safe_read_leb128<uint32_t>(iter);
    ensure(table_idx < mod.tables.size(), "unknown table");

    stack.apply(std::array<valtype, 0>(), std::array{valtype::i32});
    nextop();
}
HANDLER(table_fill) {
    auto table_idx = safe_read_leb128<uint32_t>(iter);
    ensure(table_idx < mod.tables.size(), "unknown table");

    stack.apply(
        std::array{valtype::i32, mod.tables[table_idx].type, valtype::i32},
        std::array<valtype, 0>());
    nextop();
}

consteval std::array<ValidationHandler *, 256> make_fc_funcs() {
    std::array<ValidationHandler *, 256> funcs{};
    funcs.fill(&validate_missing);

#define V(name, _, byte) funcs[byte] = &validate_##name;
    FOREACH_INSTRUCTION(V)
#undef V

    return funcs;
}

HANDLER(multibyte) {
    static auto fc_funcs = make_fc_funcs();

    [[clang::musttail]] return fc_funcs[safe_read_leb128<uint32_t>(iter)](
        mod, iter, fn, stack, control_stack);
}

void Module::validate(safe_byte_iterator &iter, FunctionShell &fn) {
    if (!fn.start) {
        // skip imported functions
        return;
    }

    auto stack = WasmStack();

    auto control_stack = std::vector<ControlFlow>(
        {ControlFlow(fn.type.results, fn.type, false, Function())});

    return funcs[*iter++](*this, iter, fn, stack, control_stack);
}

#undef ensure

} // namespace mitey
