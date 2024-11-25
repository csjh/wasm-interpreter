#include "module.hpp"
#include "instance.hpp"
#include "spec.hpp"

#ifdef WASM_DEBUG
#include <iostream>
#endif

namespace mitey {
safe_byte_iterator::safe_byte_iterator(uint8_t *begin, uint8_t *end)
    : iter(begin), end(end) {}

uint8_t safe_byte_iterator::operator*() const {
    if (iter >= end) {
        throw malformed_error("unexpected end");
    }
    return *iter;
}

uint8_t safe_byte_iterator::operator[](ssize_t n) const {
    if (iter + n >= end) {
        throw malformed_error("unexpected end");
    }
    return iter[n];
}

safe_byte_iterator &safe_byte_iterator::operator++() {
    if (iter == end) {
        throw malformed_error("unexpected end");
    }
    ++iter;
    return *this;
}

safe_byte_iterator safe_byte_iterator::operator++(int) {
    if (iter == end) {
        throw malformed_error("unexpected end");
    }
    return safe_byte_iterator(iter++, end);
}

safe_byte_iterator safe_byte_iterator::operator+(size_t n) const {
    if (iter + n > end) {
        throw malformed_error("length out of bounds");
    }
    return safe_byte_iterator(iter + n, end);
}

safe_byte_iterator &safe_byte_iterator::operator+=(size_t n) {
    if (iter + n > end) {
        throw malformed_error("unexpected end");
    }
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
        throw malformed_error("length out of bounds");
    }
    return iter;
}

bool safe_byte_iterator::empty() const { return iter == end; }

bool safe_byte_iterator::has_n_left(size_t n) const { return iter + n <= end; }

std::tuple<uint32_t, uint32_t> get_limits(safe_byte_iterator &iter,
                                          uint32_t upper_limit) {
    uint32_t flags = safe_read_leb128<uint32_t, 1>(iter);
    if (flags != 0 && flags != 1) {
        throw malformed_error("integer too large");
    }
    uint32_t initial = safe_read_leb128<uint32_t>(iter);
    uint32_t max = flags == 1 ? safe_read_leb128<uint32_t>(iter) : upper_limit;
    return {initial, max};
}

std::tuple<uint32_t, uint32_t> get_memory_limits(safe_byte_iterator &iter) {
    auto [initial, max] = get_limits(iter, Module::MAX_PAGES);
    if (initial > Module::MAX_PAGES || max > Module::MAX_PAGES) {
        throw validation_error(
            "memory size must be at most 65536 pages (4GiB)");
    }
    if (max < initial) {
        throw validation_error("size minimum must not be greater than maximum");
    }
    return {initial, max};
}

std::tuple<uint32_t, uint32_t> get_table_limits(safe_byte_iterator &iter) {
    auto [initial, max] =
        get_limits(iter, std::numeric_limits<uint32_t>::max());
    if (max < initial) {
        throw validation_error("size minimum must not be greater than maximum");
    }
    return {initial, max};
}

void Module::validate_const(safe_byte_iterator &iter, valtype expected) {
    std::vector<valtype> stack_types;

#define OP(ty, op)                                                             \
    {                                                                          \
        if (stack_types.size() < 2) {                                          \
            throw validation_error("type mismatch");                           \
        }                                                                      \
        if (stack_types[stack_types.size() - 1] != stack_types.back()) {       \
            throw validation_error("type mismatch");                           \
        }                                                                      \
        if (stack_types.back() != valtype::ty) {                               \
            throw validation_error("type mismatch");                           \
        }                                                                      \
        stack_types.pop_back();                                                \
        break;                                                                 \
    }
#define I32_OP(op) OP(i32, op)
#define I64_OP(op) OP(i64, op)

    while (1) {
        uint8_t byte = *iter++;
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
            uint32_t global_idx = safe_read_leb128<uint32_t>(iter);
            if (global_idx >= globals.size() || !globals[global_idx].import) {
                throw validation_error("unknown global " +
                                       std::to_string(global_idx));
            }
            if (globals[global_idx].mutability != mut::const_) {
                throw validation_error("constant expression required");
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
            uint32_t reftype = safe_read_leb128<uint32_t>(iter);
            if (!is_reftype(reftype)) {
                throw validation_error("type mismatch");
            }
            stack_types.push_back(static_cast<valtype>(reftype));
            break;
        }
        case ref_func: {
            uint32_t func_idx = safe_read_leb128<uint32_t>(iter);
            if (func_idx >= functions.size()) {
                throw validation_error("unknown function");
            }
            // implicit declaration
            functions[func_idx].is_declared = true;
            stack_types.push_back(valtype::funcref);
            break;
        }
        default:
            if (is_instruction(byte)) {
                throw validation_error("constant expression required");
            } else {
                throw malformed_error("illegal opcode");
            }
        }
    }

#undef OP
#undef I32_OP
#undef I64_OP

    if (stack_types.size() != 1 || stack_types[0] != expected) {
        throw validation_error("type mismatch");
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
        throw malformed_error("unexpected end");
    }

    safe_byte_iterator iter(bytes.get(), bytes.get() + length);

    if (std::memcmp(reinterpret_cast<char *>(iter.get_with_at_least(4)),
                    "\0asm", 4) != 0) {
        throw malformed_error("magic header not detected");
    }
    iter += 4;

    if (length < 8) {
        throw malformed_error("unexpected end");
    }

    if (*reinterpret_cast<uint32_t *>(iter.get_with_at_least(4)) != 1) {
        throw malformed_error("unknown binary version");
    }
    iter += sizeof(uint32_t);

    auto skip_custom_section = [&]() {
        while (!iter.empty() && *iter == 0) [[unlikely]] {
            ++iter;
            uint32_t section_length = safe_read_leb128<uint32_t>(iter);
            safe_byte_iterator start = iter;

            uint32_t name_length = safe_read_leb128<uint32_t>(iter);
            if (!is_valid_utf8(iter.get_with_at_least(name_length),
                               (iter + name_length).unsafe_ptr())) {
                throw malformed_error("malformed UTF-8 encoding");
            }

            if (start + section_length < iter) {
                throw malformed_error("unexpected end");
            }

            iter = start + section_length;
        }
    };

    auto section = [&](
                       uint32_t id, std::function<void()> body,
                       std::function<void()> else_ = [] {}) {
        if (!iter.empty() && *iter == id) {
            ++iter;
            uint32_t section_length = safe_read_leb128<uint32_t>(iter);
            if (!iter.has_n_left(section_length)) {
                throw malformed_error("length out of bounds");
            }
            safe_byte_iterator section_start = iter;

            body();

            if (iter - section_start != section_length) {
                throw malformed_error("section size mismatch");
            }

            // todo: remove this when validation separates
            if (!iter.empty() && *iter == id) {
                throw malformed_error("unexpected content after last section");
            }
        } else if (!iter.empty() && *iter > 12) {
            throw malformed_error("malformed section id");
        } else {
            else_();
        }
    };

    skip_custom_section();

    // type section
    section(1, [&] {
        uint32_t n_types = safe_read_leb128<uint32_t>(iter);

        types.reserve(n_types);

        for (uint32_t i = 0; i < n_types; ++i) {
            if (iter.empty()) {
                throw malformed_error("unexpected end of section or function");
            }

            if (*iter != 0x60) {
                throw malformed_error("integer representation too long");
                // throw validation_error("invalid function type");
            }
            ++iter;

            Signature fn{{}, {}};

            uint32_t n_params = safe_read_leb128<uint32_t>(iter);
            fn.params.reserve(n_params);
            for (uint32_t j = 0; j < n_params; ++j) {
                if (!is_valtype(iter[j])) {
                    throw validation_error("invalid parameter type");
                }
                fn.params.push_back(static_cast<valtype>(iter[j]));
            }
            iter += n_params;

            uint32_t n_results = safe_read_leb128<uint32_t>(iter);
            fn.results.reserve(n_results);
            for (uint32_t j = 0; j < n_results; ++j) {
                if (!is_valtype(iter[j])) {
                    throw validation_error("invalid result type");
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
        uint32_t n_imports = safe_read_leb128<uint32_t>(iter);

        for (uint32_t i = 0; i < n_imports; i++) {
            if (iter.empty()) {
                throw malformed_error("unexpected end of section or function");
            }

            uint32_t module_len = safe_read_leb128<uint32_t>(iter);
            if (!is_valid_utf8(iter.get_with_at_least(module_len),
                               (iter + module_len).unsafe_ptr())) {
                throw malformed_error("malformed UTF-8 encoding");
            }
            std::string module(
                reinterpret_cast<char *>(iter.get_with_at_least(module_len)),
                module_len);
            iter += module_len;

            uint32_t field_len = safe_read_leb128<uint32_t>(iter);
            if (!is_valid_utf8(iter.get_with_at_least(field_len),
                               (iter + field_len).unsafe_ptr())) {
                throw malformed_error("malformed UTF-8 encoding");
            }
            std::string field(
                reinterpret_cast<char *>(iter.get_with_at_least(field_len)),
                field_len);
            iter += field_len;

            uint32_t kind = *iter++;
            if (!is_imexdesc(kind)) {
                throw malformed_error("malformed import kind");
            }
            ImExDesc desc = static_cast<ImExDesc>(kind);
            imports[module][field] = desc;

            auto specifier = std::make_optional(std::make_pair(module, field));

            if (desc == ImExDesc::func) {
                // func
                uint32_t typeidx = safe_read_leb128<uint32_t>(iter);
                if (typeidx >= types.size()) {
                    throw validation_error("unknown type");
                }
                functions.push_back({nullptr, types[typeidx], {}, specifier});
                n_fn_imports++;
            } else if (desc == ImExDesc::table) {
                // table
                uint32_t reftype = safe_read_leb128<uint32_t>(iter);
                if (!is_reftype(reftype)) {
                    throw malformed_error("malformed reference type");
                }

                auto [initial, max] = get_table_limits(iter);
                tables.push_back(
                    {initial, max, static_cast<valtype>(reftype), specifier});
            } else if (desc == ImExDesc::mem) {
                // mem
                if (memory.exists) {
                    throw validation_error("multiple memories");
                }

                auto [initial, max] = get_memory_limits(iter);
                this->memory = {initial, max, true, specifier};
            } else if (desc == ImExDesc::global) {
                // global
                uint32_t maybe_valtype = safe_read_leb128<uint32_t>(iter);
                if (!is_valtype(maybe_valtype)) {
                    throw malformed_error("invalid global type");
                }
                uint8_t mutability = *iter++;
                if (!is_mut(mutability)) {
                    throw malformed_error("malformed mutability");
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
        uint32_t n_functions = safe_read_leb128<uint32_t>(iter);

        functions.reserve(n_functions);

        for (uint32_t i = 0; i < n_functions; ++i) {
            if (iter.empty()) {
                throw malformed_error("unexpected end of section or function");
            }

            uint32_t type_idx = safe_read_leb128<uint32_t>(iter);
            if (type_idx >= types.size()) {
                throw validation_error("unknown type");
            }
            functions.push_back({nullptr, types[type_idx], {}, std::nullopt});
        }
    });

    skip_custom_section();

    // table section
    section(4, [&] {
        uint32_t n_tables = safe_read_leb128<uint32_t>(iter);
        tables.reserve(n_tables);

        for (uint32_t i = 0; i < n_tables; ++i) {
            if (iter.empty()) {
                throw malformed_error("unexpected end of section or function");
            }

            uint8_t elem_type = *iter++;
            if (!is_reftype(elem_type)) {
                throw validation_error("invalid table element type");
            }

            auto [initial, max] = get_table_limits(iter);
            tables.push_back(
                {initial, max, static_cast<valtype>(elem_type), std::nullopt});
        }
    });

    skip_custom_section();

    // memory section
    section(5, [&] {
        uint32_t n_memories = safe_read_leb128<uint32_t>(iter);
        if (n_memories > 1) {
            throw validation_error("multiple memories");
        } else if (n_memories == 1) {
            if (iter.empty()) {
                throw malformed_error("unexpected end of section or function");
            }
            if (memory.exists) {
                throw validation_error("multiple memories");
            }

            auto [initial, max] = get_memory_limits(iter);
            memory = {initial, max, true, std::nullopt};
        }
    });

    skip_custom_section();

    // global section
    section(6, [&] {
        uint32_t n_globals = safe_read_leb128<uint32_t>(iter);

        globals.reserve(n_globals);

        for (uint32_t i = 0; i < n_globals; ++i) {
            if (iter.empty()) {
                throw malformed_error("unexpected end of section or function");
            }

            uint8_t maybe_type = *iter++;
            if (!is_valtype(maybe_type)) {
                throw malformed_error("invalid global type");
            }
            valtype type = static_cast<valtype>(maybe_type);

            uint8_t maybe_mut = *iter++;
            if (!is_mut(maybe_mut)) {
                throw malformed_error("malformed mutability");
            }
            mut global_mut = static_cast<mut>(maybe_mut);

            globals.push_back(
                {type, global_mut, iter.unsafe_ptr(), std::nullopt});

            validate_const(iter, type);
        }
    });

    skip_custom_section();

    // export section
    section(7, [&] {
        uint32_t n_exports = safe_read_leb128<uint32_t>(iter);

        for (uint32_t i = 0; i < n_exports; ++i) {
            if (iter.empty()) {
                throw malformed_error("unexpected end of section or function");
            }

            uint32_t name_len = safe_read_leb128<uint32_t>(iter);
            std::string name(
                reinterpret_cast<char *>(iter.get_with_at_least(name_len)),
                name_len);
            iter += name_len;

            uint8_t desc = *iter++;
            if (!is_imexdesc(desc)) {
                throw validation_error("invalid export description");
            }
            ImExDesc export_desc = static_cast<ImExDesc>(desc);

            uint32_t idx = safe_read_leb128<uint32_t>(iter);

            if (exports.contains(name)) {
                throw validation_error("duplicate export name");
            }

            if (export_desc == ImExDesc::func) {
                if (idx >= functions.size()) {
                    throw validation_error("unknown function");
                }
                // implicit declaration
                functions[idx].is_declared = true;
            } else if (export_desc == ImExDesc::table) {
                if (idx >= tables.size()) {
                    throw validation_error("unknown table");
                }
            } else if (export_desc == ImExDesc::mem) {
                if (idx != 0 || !memory.exists) {
                    throw validation_error("unknown memory");
                }
            } else if (export_desc == ImExDesc::global) {
                if (idx >= globals.size()) {
                    throw validation_error("unknown global");
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
                throw validation_error("unknown function");
            }
        },
        [&] { start = std::numeric_limits<uint32_t>::max(); });

    skip_custom_section();

    // element section
    section(9, [&] {
        uint32_t n_elements = safe_read_leb128<uint32_t>(iter);

        elements.reserve(n_elements);

        element_start = iter.unsafe_ptr();
        for (uint32_t i = 0; i < n_elements; i++) {
            /*
            why is this not needed
            if (iter.empty()) {
                throw malformed_error("unexpected end of section or
            function");
            }
            */
            uint32_t flags = safe_read_leb128<uint32_t>(iter);
            if (flags & ~0b111) {
                throw validation_error("invalid element flags");
            }

            if (flags & 1) {
                if (flags & 0b10) {
                    if (flags & 0b100) {
                        // flags = 7
                        // characteristics: declarative, elem type + exprs
                        uint32_t maybe_reftype = *iter++;
                        if (!is_reftype(maybe_reftype)) {
                            throw malformed_error("malformed reference type");
                        }
                        valtype reftype = static_cast<valtype>(maybe_reftype);
                        uint32_t n_elements = safe_read_leb128<uint32_t>(iter);
                        for (uint32_t j = 0; j < n_elements; j++) {
                            // validate_const sets is_declared
                            validate_const(iter, reftype);
                        }
                        elements.emplace_back(ElementShell{reftype});
                    } else {
                        // flags = 3
                        // characteristics: declarative, elem kind + indices
                        uint8_t elemkind = *iter++;
                        if (elemkind != 0) {
                            throw validation_error("invalid elemkind");
                        }
                        uint32_t n_elements = safe_read_leb128<uint32_t>(iter);
                        for (uint32_t j = 0; j < n_elements; j++) {
                            uint32_t elem_idx =
                                safe_read_leb128<uint32_t>(iter);
                            if (elem_idx >= functions.size()) {
                                throw validation_error("unknown function");
                            }
                            functions[elem_idx].is_declared = true;
                        }
                        elements.emplace_back(ElementShell{valtype::funcref});
                    }
                } else {
                    if (flags & 0b100) {
                        // flags = 5
                        // characteristics: passive, elem type + exprs
                        uint8_t maybe_reftype = *iter++;
                        if (!is_reftype(maybe_reftype)) {
                            throw malformed_error("malformed reference type");
                        }
                        valtype reftype = static_cast<valtype>(maybe_reftype);
                        uint32_t n_elements = safe_read_leb128<uint32_t>(iter);
                        for (uint32_t j = 0; j < n_elements; j++) {
                            validate_const(iter, reftype);
                        }
                        elements.emplace_back(ElementShell{reftype});
                    } else {
                        // flags = 1
                        // characteristics: passive, elem kind + indices
                        uint8_t elemkind = *iter++;
                        if (elemkind != 0) {
                            throw validation_error("invalid elemkind");
                        }
                        uint32_t n_elements = safe_read_leb128<uint32_t>(iter);
                        for (uint32_t j = 0; j < n_elements; j++) {
                            uint32_t elem_idx =
                                safe_read_leb128<uint32_t>(iter);
                            if (elem_idx >= functions.size()) {
                                throw validation_error("unknown function");
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
                    throw validation_error("unknown table");
                }

                valtype reftype;

                /* uint32_t offset = */ validate_const(iter, valtype::i32);
                uint16_t reftype_or_elemkind = flags & 0b10 ? *iter++ : 256;
                uint32_t n_elements = safe_read_leb128<uint32_t>(iter);

                if (flags & 0b100) {
                    // flags = 4 or 6
                    // characteristics: active, elem type + exprs
                    if (reftype_or_elemkind == 256)
                        reftype_or_elemkind =
                            static_cast<uint16_t>(valtype::funcref);
                    if (!is_reftype(reftype_or_elemkind)) {
                        throw malformed_error("malformed reference type");
                    }
                    reftype = static_cast<valtype>(reftype_or_elemkind);
                    if (tables[table_idx].type != reftype) {
                        throw validation_error("type mismatch");
                    }
                    for (uint32_t j = 0; j < n_elements; j++) {
                        validate_const(iter, reftype);
                    }
                } else {
                    if (reftype_or_elemkind == 256)
                        reftype_or_elemkind = 0;
                    if (reftype_or_elemkind != 0) {
                        throw validation_error("invalid elemkind");
                    }
                    reftype = valtype::funcref;
                    if (tables[table_idx].type != reftype) {
                        throw validation_error("type mismatch");
                    }
                    // flags = 0 or 2
                    // characteristics: active, elem kind + indices
                    for (uint32_t j = 0; j < n_elements; j++) {
                        uint32_t elem_idx = safe_read_leb128<uint32_t>(iter);
                        if (elem_idx >= functions.size()) {
                            throw validation_error("unknown function");
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
    bool has_data_count = false;
    section(12, [&] {
        n_data = safe_read_leb128<uint32_t>(iter);
        has_data_count = true;
    });

    skip_custom_section();

    // code section
    section(
        10,
        [&] {
            uint32_t n_functions = safe_read_leb128<uint32_t>(iter);

            if (n_functions + n_fn_imports != functions.size()) {
                throw malformed_error(
                    "function and code section have inconsistent lengths");
            }

            for (FunctionShell &fn : functions) {
                if (fn.import) {
                    // skip imported functions
                    continue;
                }

                fn.locals = fn.type.params;

                uint32_t function_length = safe_read_leb128<uint32_t>(iter);

                safe_byte_iterator start(iter.unsafe_ptr(),
                                         iter.unsafe_ptr() + function_length);

                uint32_t n_local_decls = safe_read_leb128<uint32_t>(iter);
                while (n_local_decls--) {
                    uint32_t n_locals = safe_read_leb128<uint32_t>(iter);
                    uint8_t type = *iter++;
                    if (!is_valtype(type)) {
                        throw validation_error("invalid local type");
                    }
                    while (n_locals--) {
                        fn.locals.push_back(static_cast<valtype>(type));
                        if (fn.locals.size() > MAX_LOCALS) {
                            throw malformed_error("too many locals");
                        }
                    }
                }
                auto body_length = function_length - (iter - start);
                fn.start = iter.get_with_at_least(body_length);

                safe_byte_iterator fn_iter = iter;
                validate(fn_iter, fn);
                if (fn_iter[-1] != static_cast<uint8_t>(Instruction::end)) {
                    throw malformed_error("END opcode expected");
                }
                if (fn_iter - start != function_length) {
                    throw malformed_error("section size mismatch");
                }
                iter += fn_iter - iter;
            }
        },
        [&] {
            if (functions.size() != n_fn_imports) {
                throw malformed_error(
                    "function and code section have inconsistent lengths");
            }
        });

    skip_custom_section();

    // data section
    section(
        11,
        [&] {
            uint32_t section_n_data = safe_read_leb128<uint32_t>(iter);
            if (has_data_count && n_data != section_n_data) {
                throw malformed_error("data count and data section have "
                                      "inconsistent lengths");
            }

            for (uint32_t i = 0; i < section_n_data; i++) {
                if (iter.empty()) {
                    throw malformed_error(
                        "unexpected end of section or function");
                }

                uint32_t segment_flag = safe_read_leb128<uint32_t>(iter);
                if (segment_flag & ~0b11) {
                    throw validation_error("invalid data segment flag");
                }

                uint32_t memidx =
                    segment_flag & 0b10 ? safe_read_leb128<uint32_t>(iter) : 0;

                if (memidx != 0) {
                    throw validation_error("unknown memory " +
                                           std::to_string(memidx));
                }

                if (segment_flag & 1) {
                    // passive segment

                    uint32_t data_length = safe_read_leb128<uint32_t>(iter);
                    if (!iter.has_n_left(data_length)) {
                        throw malformed_error(
                            "unexpected end of section or function");
                    }
                    std::span<uint8_t> data(iter.get_with_at_least(data_length),
                                            data_length);
                    iter += data_length;

                    data_segments.emplace_back(Segment{memidx, data, nullptr});
                } else {
                    // active segment
                    if (!memory.exists) {
                        throw validation_error("unknown memory 0");
                    }

                    uint8_t *initializer = iter.unsafe_ptr();
                    validate_const(iter, valtype::i32);
                    uint32_t data_length = safe_read_leb128<uint32_t>(iter);
                    if (!iter.has_n_left(data_length)) {
                        throw malformed_error(
                            "unexpected end of section or function");
                    }

                    std::span<uint8_t> data(iter.get_with_at_least(data_length),
                                            data_length);
                    iter += data_length;

                    // todo: this has to be instantiated
                    data_segments.emplace_back(
                        Segment{memidx, data, initializer});
                }
            }
        },
        [&] {
            if (has_data_count && n_data != 0) {
                throw malformed_error("data count and data section have "
                                      "inconsistent lengths");
            }
        });

    skip_custom_section();

    if (!iter.empty()) {
        throw malformed_error("unexpected content after last section");
    }
}

static inline void _ensure(bool condition, const std::string &msg) {
    if (!condition) [[unlikely]] {
        throw validation_error(msg);
    }
}

#define ensure(condition, msg) _ensure(condition, msg)

void Module::validate(safe_byte_iterator &iter, FunctionShell &fn) {
    if (!fn.start) {
        // skip imported functions
        return;
    }

    current_fn = fn;
    control_stack.push_back(fn.type.results);

    validate(iter, fn.type, true);

    ensure(control_stack.size() == 1,
           "control stack not empty at end of function");
    control_stack.clear();
}

class WasmStack : protected std::vector<valtype> {
    bool polymorphized = false;

    class infinite_iterator {
        std::vector<valtype>::const_reverse_iterator start, end;

      public:
        infinite_iterator(const std::vector<valtype> &vec)
            : start(vec.rbegin()), end(vec.rend()) {}

        valtype operator*() const {
            if (start == end)
                return valtype::empty;
            return *start;
        }
        infinite_iterator &operator++() {
            if (start != end)
                ++start;
            return *this;
        }
    };

    infinite_iterator rbegin() const { return infinite_iterator(*this); }

  public:
    bool check(const std::vector<valtype> &expected) {
        // this guarantees non-polymorphized stacks don't accidentally use the
        // valtype::empty from the infinite_iterator
        if (expected.size() > size())
            return false;

        return std::equal(
            expected.rbegin(), expected.rend(), rbegin(),
            [](valtype a, valtype b) { return b == valtype::empty || a == b; });
    }

    bool operator==(const std::vector<valtype> &rhs) {
        return check(rhs) && (rhs.size() >= std::vector<valtype>::size());
    }

    void polymorphize() {
        polymorphized = true;
        clear();
    }

    void push(valtype ty) { push(std::vector<valtype>{ty}); }
    void push(const std::vector<valtype> &values) {
        insert(end(), values.begin(), values.end());
    }
    void pop(valtype expected_ty) { pop(std::vector<valtype>{expected_ty}); }
    void pop(const std::vector<valtype> &expected) {
        ensure(check(expected), "type mismatch");

        auto materialized =
            std::min(std::vector<valtype>::size(), expected.size());

        erase(end() - materialized, end());
    }

    bool empty() const {
        return !polymorphized && std::vector<valtype>::empty();
    }

    bool can_be_anything() const {
        return polymorphized && std::vector<valtype>::empty();
    }

    valtype back() const {
        ensure(!empty(), "type mismatch");
        return *rbegin();
    }

    unsigned long size() const {
        return polymorphized ? static_cast<unsigned long>(-1)
                             : std::vector<valtype>::size();
    }
};

void Module::validate(safe_byte_iterator &iter, const Signature &signature,
                      bool is_func) {
    WasmStack stack;
    if (!is_func) {
        stack.push(signature.params);
    }

    auto apply = [&](Signature signature) {
        stack.pop(signature.params);
        stack.push(signature.results);
    };

    auto check_br = [&](uint32_t depth) {
        ensure(depth < control_stack.size(), "unknown label");
        auto &expected_at_target =
            control_stack[control_stack.size() - depth - 1];
        stack.pop(expected_at_target);
        stack.push(expected_at_target);
    };

#define LOAD(type, stacktype)                                                  \
    {                                                                          \
        uint32_t a = safe_read_leb128<uint32_t>(iter);                         \
        ensure(memory.exists, "unknown memory");                               \
        if (a >= 32) {                                                         \
            throw malformed_error("malformed memop flags");                    \
        }                                                                      \
        uint32_t align = 1 << a;                                               \
        ensure(align <= sizeof(type),                                          \
               "alignment must not be larger than natural");                   \
        /* uint32_t offset = */ safe_read_leb128<uint32_t>(iter);              \
        apply({{valtype::i32}, {stacktype}});                                  \
        break;                                                                 \
    }

#define STORE(type, stacktype)                                                 \
    {                                                                          \
        uint32_t a = safe_read_leb128<uint32_t>(iter);                         \
        if ((1 << 6) & a) {                                                    \
            a -= 1 << 6;                                                       \
            /* todo: test multi memory proposal */                             \
            a = safe_read_leb128<uint32_t>(iter);                              \
        } else {                                                               \
            ensure(memory.exists, "unknown memory");                           \
        }                                                                      \
        uint32_t align = 1 << a;                                               \
        ensure(align <= sizeof(type),                                          \
               "alignment must not be larger than natural");                   \
        /* uint32_t offset = */ safe_read_leb128<uint32_t>(iter);              \
        apply({{valtype::i32, stacktype}, {}});                                \
        break;                                                                 \
    }

    using enum Instruction;
    while (1) {
        uint8_t byte = *iter++;

#ifdef WASM_DEBUG
        std::cerr << "reading instruction " << instructions[byte].c_str()
                  << " at " << iter - bytes.get() << std::endl;
        std::cerr << "control stack size: " << control_stack.size()
                  << std::endl;
        std::cerr << "stack size: " << stack.size() << std::endl;
        std::cerr << "control stack: ";
        for (auto &target : control_stack) {
            std::cerr << target.size() << " ";
        }
        std::cerr << std::endl;
#endif

        ensure(is_instruction(byte), "invalid instruction");
        switch (static_cast<Instruction>(byte)) {
        case unreachable:
            stack.polymorphize();
            break;
        case nop:
            break;
        case block: {
            auto signature = Signature::read_blocktype(types, iter);

            stack.pop(signature.params);

            uint8_t *block_start = iter.unsafe_ptr();

            control_stack.push_back(signature.results);
            validate(iter, signature);
            control_stack.pop_back();

            block_ends[block_start] = iter.unsafe_ptr();

            stack.push(signature.results);
            break;
        }
        case loop: {
            auto signature = Signature::read_blocktype(types, iter);

            stack.pop(signature.params);

            control_stack.push_back(signature.params);
            validate(iter, signature);
            control_stack.pop_back();

            stack.push(signature.results);
            break;
        }
        case if_: {
            stack.pop(valtype::i32);

            auto signature = Signature::read_blocktype(types, iter);

            stack.pop(signature.params);
            control_stack.push_back(signature.results);

            uint8_t *if_start = iter.unsafe_ptr();
            validate(iter, signature);
            uint8_t *else_start = iter.unsafe_ptr();

            // validate else branch if previous instruction was else
            if (iter[-1] == static_cast<uint8_t>(else_)) {
                validate(iter, signature);
            } else {
                // if there's no else branch, params and results must match
                ensure(signature.params == signature.results, "type mismatch");
                // if there's no else branch, we want false to jump to the end
                // instruction
                else_start--;
            }
            control_stack.pop_back();
            stack.push(signature.results);

            if_jumps[if_start] = {else_start, iter.unsafe_ptr()};
            break;
        }
        // else is basically an end to an if
        case else_:
        case end:
            ensure(stack == signature.results, "type mismatch");
            return;
        case br: {
            check_br(safe_read_leb128<uint32_t>(iter));
            stack.polymorphize();
            break;
        }
        case br_if: {
            stack.pop(valtype::i32);
            uint32_t depth = safe_read_leb128<uint32_t>(iter);
            check_br(depth);
            break;
        }
        case br_table: {
            stack.pop(valtype::i32);
            uint32_t n_targets = safe_read_leb128<uint32_t>(iter);

            std::vector<uint32_t> targets;
            for (uint32_t i = 0; i <= n_targets; ++i) {
                uint32_t target = safe_read_leb128<uint32_t>(iter);
                ensure(target < control_stack.size(), "unknown label");
                targets.push_back(target);
            }
            auto &default_target =
                control_stack[control_stack.size() - targets.back() - 1];
            for (uint32_t depth : targets) {
                auto target = control_stack[control_stack.size() - depth - 1];
                if (stack.can_be_anything()) {
                    ensure(stack.check(target), "type mismatch");
                    ensure(default_target.size() == target.size(),
                           "type mismatch");
                } else {
                    check_br(depth);
                    ensure(default_target == target, "type mismatch");
                }
            }
            stack.polymorphize();
            break;
        }
        case return_:
            check_br(control_stack.size() - 1);
            stack.polymorphize();
            break;
        case call: {
            uint32_t fn_idx = safe_read_leb128<uint32_t>(iter);
            ensure(fn_idx < functions.size(), "unknown function");

            FunctionShell &fn = functions[fn_idx];
            apply(fn.type);
            break;
        }
        case call_indirect: {
            stack.pop(valtype::i32);

            uint32_t type_idx = safe_read_leb128<uint32_t>(iter);
            ensure(type_idx < types.size(), "unknown type");

            uint32_t table_idx = safe_read_leb128<uint32_t>(iter);
            ensure(table_idx < tables.size(), "unknown table");
            ensure(tables[table_idx].type == valtype::funcref, "type mismatch");

            apply(types[type_idx]);
            break;
        }
        case drop:
            ensure(!stack.empty(), "type mismatch");
            stack.pop(stack.back());
            break;
        case select: {
            ensure(stack.size() >= 3, "type mismatch");
            // first pop the condition
            stack.pop(valtype::i32);

            valtype ty = stack.back();
            ensure(ty == valtype::empty || is_numtype(ty), "type mismatch");

            // then apply the dynamic type
            apply({{ty, ty}, {ty}});
            break;
        }
        case select_t: {
            uint32_t n_results = safe_read_leb128<uint32_t>(iter);
            ensure(n_results == 1, "invalid result arity");
            uint32_t maybe_valtype = *iter++;
            ensure(is_valtype(maybe_valtype), "invalid result type");

            ensure(stack.size() >= 3, "type mismatch");
            // first pop the condition
            stack.pop(valtype::i32);
            valtype ty = stack.back();
            // then apply the dynamic type
            apply({{ty, ty}, {ty}});
            break;
        }
        case localget: {
            uint32_t local_idx = safe_read_leb128<uint32_t>(iter);
            ensure(local_idx < current_fn.locals.size(), "unknown local");
            valtype local_ty = current_fn.locals[local_idx];
            apply({{}, {local_ty}});
            break;
        }
        case localset: {
            uint32_t local_idx = safe_read_leb128<uint32_t>(iter);
            ensure(local_idx < current_fn.locals.size(), "unknown local");
            valtype local_ty = current_fn.locals[local_idx];
            apply({{local_ty}, {}});
            break;
        }
        case localtee: {
            uint32_t local_idx = safe_read_leb128<uint32_t>(iter);
            ensure(local_idx < current_fn.locals.size(), "unknown local");
            valtype locaL_ty = current_fn.locals[local_idx];
            apply({{locaL_ty}, {locaL_ty}});
            break;
        }
        case tableget: {
            uint32_t table_idx = safe_read_leb128<uint32_t>(iter);
            ensure(table_idx < tables.size(), "unknown table");
            valtype table_ty = tables[table_idx].type;
            apply({{valtype::i32}, {table_ty}});
            break;
        }
        case tableset: {
            uint32_t table_idx = safe_read_leb128<uint32_t>(iter);
            ensure(table_idx < tables.size(), "unknown table");
            valtype table_ty = tables[table_idx].type;
            apply({{valtype::i32, table_ty}, {}});
            break;
        }
        case globalget: {
            uint32_t global_idx = safe_read_leb128<uint32_t>(iter);
            ensure(global_idx < globals.size(), "unknown global");
            valtype global_ty = globals[global_idx].type;
            apply({{}, {global_ty}});
            break;
        }
        case globalset: {
            uint32_t global_idx = safe_read_leb128<uint32_t>(iter);
            ensure(global_idx < globals.size(), "unknown global");
            ensure(globals[global_idx].mutability == mut::var,
                   "global is immutable");
            valtype global_ty = globals[global_idx].type;
            apply({{global_ty}, {}});
            break;
        }
        case memorysize: {
            if (*iter++ != 0)
                throw malformed_error("zero byte expected");
            ensure(memory.exists, "unknown memory");
            apply({{}, {valtype::i32}});
            break;
        }
        case memorygrow: {
            if (*iter++ != 0)
                throw malformed_error("zero byte expected");
            ensure(memory.exists, "unknown memory");
            apply({{valtype::i32}, {valtype::i32}});
            break;
        }
        case i32const:
            safe_read_sleb128<uint32_t>(iter);
            apply({{}, {valtype::i32}});
            break;
        case i64const:
            safe_read_sleb128<uint64_t>(iter);
            apply({{}, {valtype::i64}});
            break;
        case f32const: {
            iter += sizeof(float);
            apply({{}, {valtype::f32}});
            break;
        }
        case f64const:
            iter += sizeof(double);
            apply({{}, {valtype::f64}});
            break;
        // clang-format off
        case i32load:     LOAD(uint32_t,  valtype::i32);
        case i64load:     LOAD(uint64_t,  valtype::i64);
        case f32load:     LOAD(float,     valtype::f32);
        case f64load:     LOAD(double,    valtype::f64);
        case i32load8_s:  LOAD(int8_t,    valtype::i32);
        case i32load8_u:  LOAD(uint8_t,   valtype::i32);
        case i32load16_s: LOAD(int16_t,   valtype::i32);
        case i32load16_u: LOAD(uint16_t,  valtype::i32);
        case i64load8_s:  LOAD(int8_t,    valtype::i64);
        case i64load8_u:  LOAD(uint8_t,   valtype::i64);
        case i64load16_s: LOAD(int16_t,   valtype::i64);
        case i64load16_u: LOAD(uint16_t,  valtype::i64);
        case i64load32_s: LOAD(int32_t,   valtype::i64);
        case i64load32_u: LOAD(uint32_t,  valtype::i64);
        case i32store:    STORE(uint32_t, valtype::i32);
        case i64store:    STORE(uint64_t, valtype::i64);
        case f32store:    STORE(float,    valtype::f32);
        case f64store:    STORE(double,   valtype::f64);
        case i32store8:   STORE(uint8_t,  valtype::i32);
        case i32store16:  STORE(uint16_t, valtype::i32);
        case i64store8:   STORE(uint8_t,  valtype::i64);
        case i64store16:  STORE(uint16_t, valtype::i64);
        case i64store32:  STORE(uint32_t, valtype::i64);
        case i32eqz:      apply({{valtype::i32              }, {valtype::i32}}); break;
        case i64eqz:      apply({{valtype::i64              }, {valtype::i32}}); break;
        case i32eq:       apply({{valtype::i32, valtype::i32}, {valtype::i32}}); break;
        case i64eq:       apply({{valtype::i64, valtype::i64}, {valtype::i32}}); break;
        case i32ne:       apply({{valtype::i32, valtype::i32}, {valtype::i32}}); break;
        case i64ne:       apply({{valtype::i64, valtype::i64}, {valtype::i32}}); break;
        case i32lt_s:     apply({{valtype::i32, valtype::i32}, {valtype::i32}}); break;
        case i64lt_s:     apply({{valtype::i64, valtype::i64}, {valtype::i32}}); break;
        case i32lt_u:     apply({{valtype::i32, valtype::i32}, {valtype::i32}}); break;
        case i64lt_u:     apply({{valtype::i64, valtype::i64}, {valtype::i32}}); break;
        case i32gt_s:     apply({{valtype::i32, valtype::i32}, {valtype::i32}}); break;
        case i64gt_s:     apply({{valtype::i64, valtype::i64}, {valtype::i32}}); break;
        case i32gt_u:     apply({{valtype::i32, valtype::i32}, {valtype::i32}}); break;
        case i64gt_u:     apply({{valtype::i64, valtype::i64}, {valtype::i32}}); break;
        case i32le_s:     apply({{valtype::i32, valtype::i32}, {valtype::i32}}); break;
        case i64le_s:     apply({{valtype::i64, valtype::i64}, {valtype::i32}}); break;
        case i32le_u:     apply({{valtype::i32, valtype::i32}, {valtype::i32}}); break;
        case i64le_u:     apply({{valtype::i64, valtype::i64}, {valtype::i32}}); break;
        case i32ge_s:     apply({{valtype::i32, valtype::i32}, {valtype::i32}}); break;
        case i64ge_s:     apply({{valtype::i64, valtype::i64}, {valtype::i32}}); break;
        case i32ge_u:     apply({{valtype::i32, valtype::i32}, {valtype::i32}}); break;
        case i64ge_u:     apply({{valtype::i64, valtype::i64}, {valtype::i32}}); break;
        case f32eq:       apply({{valtype::f32, valtype::f32}, {valtype::i32}}); break;
        case f64eq:       apply({{valtype::f64, valtype::f64}, {valtype::i32}}); break;
        case f32ne:       apply({{valtype::f32, valtype::f32}, {valtype::i32}}); break;
        case f64ne:       apply({{valtype::f64, valtype::f64}, {valtype::i32}}); break;
        case f32lt:       apply({{valtype::f32, valtype::f32}, {valtype::i32}}); break;
        case f64lt:       apply({{valtype::f64, valtype::f64}, {valtype::i32}}); break;
        case f32gt:       apply({{valtype::f32, valtype::f32}, {valtype::i32}}); break;
        case f64gt:       apply({{valtype::f64, valtype::f64}, {valtype::i32}}); break;
        case f32le:       apply({{valtype::f32, valtype::f32}, {valtype::i32}}); break;
        case f64le:       apply({{valtype::f64, valtype::f64}, {valtype::i32}}); break;
        case f32ge:       apply({{valtype::f32, valtype::f32}, {valtype::i32}}); break;
        case f64ge:       apply({{valtype::f64, valtype::f64}, {valtype::i32}}); break;
        case i32clz:      apply({{valtype::i32              }, {valtype::i32}}); break;
        case i64clz:      apply({{valtype::i64              }, {valtype::i64}}); break;
        case i32ctz:      apply({{valtype::i32              }, {valtype::i32}}); break;
        case i64ctz:      apply({{valtype::i64              }, {valtype::i64}}); break;
        case i32popcnt:   apply({{valtype::i32              }, {valtype::i32}}); break;
        case i64popcnt:   apply({{valtype::i64              }, {valtype::i64}}); break;
        case i32add:      apply({{valtype::i32, valtype::i32}, {valtype::i32}}); break;
        case i64add:      apply({{valtype::i64, valtype::i64}, {valtype::i64}}); break;
        case i32sub:      apply({{valtype::i32, valtype::i32}, {valtype::i32}}); break;
        case i64sub:      apply({{valtype::i64, valtype::i64}, {valtype::i64}}); break;
        case i32mul:      apply({{valtype::i32, valtype::i32}, {valtype::i32}}); break;
        case i64mul:      apply({{valtype::i64, valtype::i64}, {valtype::i64}}); break;
        case i32div_s:    apply({{valtype::i32, valtype::i32}, {valtype::i32}}); break;
        case i64div_s:    apply({{valtype::i64, valtype::i64}, {valtype::i64}}); break;
        case i32div_u:    apply({{valtype::i32, valtype::i32}, {valtype::i32}}); break;
        case i64div_u:    apply({{valtype::i64, valtype::i64}, {valtype::i64}}); break;
        case i32rem_s:    apply({{valtype::i32, valtype::i32}, {valtype::i32}}); break;
        case i64rem_s:    apply({{valtype::i64, valtype::i64}, {valtype::i64}}); break;
        case i32rem_u:    apply({{valtype::i32, valtype::i32}, {valtype::i32}}); break;
        case i64rem_u:    apply({{valtype::i64, valtype::i64}, {valtype::i64}}); break;
        case i32and:      apply({{valtype::i32, valtype::i32}, {valtype::i32}}); break;
        case i64and:      apply({{valtype::i64, valtype::i64}, {valtype::i64}}); break;
        case i32or:       apply({{valtype::i32, valtype::i32}, {valtype::i32}}); break;
        case i64or:       apply({{valtype::i64, valtype::i64}, {valtype::i64}}); break;
        case i32xor:      apply({{valtype::i32, valtype::i32}, {valtype::i32}}); break;
        case i64xor:      apply({{valtype::i64, valtype::i64}, {valtype::i64}}); break;
        case i32shl:      apply({{valtype::i32, valtype::i32}, {valtype::i32}}); break;
        case i64shl:      apply({{valtype::i64, valtype::i64}, {valtype::i64}}); break;
        case i32shr_s:    apply({{valtype::i32, valtype::i32}, {valtype::i32}}); break;
        case i64shr_s:    apply({{valtype::i64, valtype::i64}, {valtype::i64}}); break;
        case i32shr_u:    apply({{valtype::i32, valtype::i32}, {valtype::i32}}); break;
        case i64shr_u:    apply({{valtype::i64, valtype::i64}, {valtype::i64}}); break;
        case i32rotl:     apply({{valtype::i32, valtype::i32}, {valtype::i32}}); break;
        case i64rotl:     apply({{valtype::i64, valtype::i64}, {valtype::i64}}); break;
        case i32rotr:     apply({{valtype::i32, valtype::i32}, {valtype::i32}}); break;
        case i64rotr:     apply({{valtype::i64, valtype::i64}, {valtype::i64}}); break;
        case f32abs:      apply({{valtype::f32              }, {valtype::f32}}); break;
        case f64abs:      apply({{valtype::f64              }, {valtype::f64}}); break;
        case f32neg:      apply({{valtype::f32              }, {valtype::f32}}); break;
        case f64neg:      apply({{valtype::f64              }, {valtype::f64}}); break;
        case f32ceil:     apply({{valtype::f32              }, {valtype::f32}}); break;
        case f64ceil:     apply({{valtype::f64              }, {valtype::f64}}); break;
        case f32floor:    apply({{valtype::f32              }, {valtype::f32}}); break;
        case f64floor:    apply({{valtype::f64              }, {valtype::f64}}); break;
        case f32trunc:    apply({{valtype::f32              }, {valtype::f32}}); break;
        case f64trunc:    apply({{valtype::f64              }, {valtype::f64}}); break;
        case f32nearest:  apply({{valtype::f32              }, {valtype::f32}}); break;
        case f64nearest:  apply({{valtype::f64              }, {valtype::f64}}); break;
        case f32sqrt:     apply({{valtype::f32              }, {valtype::f32}}); break;
        case f64sqrt:     apply({{valtype::f64              }, {valtype::f64}}); break;
        case f32add:      apply({{valtype::f32, valtype::f32}, {valtype::f32}}); break;
        case f64add:      apply({{valtype::f64, valtype::f64}, {valtype::f64}}); break;
        case f32sub:      apply({{valtype::f32, valtype::f32}, {valtype::f32}}); break;
        case f64sub:      apply({{valtype::f64, valtype::f64}, {valtype::f64}}); break;
        case f32mul:      apply({{valtype::f32, valtype::f32}, {valtype::f32}}); break;
        case f64mul:      apply({{valtype::f64, valtype::f64}, {valtype::f64}}); break;
        case f32div:      apply({{valtype::f32, valtype::f32}, {valtype::f32}}); break;
        case f64div:      apply({{valtype::f64, valtype::f64}, {valtype::f64}}); break;
        case f32min:      apply({{valtype::f32, valtype::f32}, {valtype::f32}}); break;
        case f64min:      apply({{valtype::f64, valtype::f64}, {valtype::f64}}); break;
        case f32max:      apply({{valtype::f32, valtype::f32}, {valtype::f32}}); break;
        case f64max:      apply({{valtype::f64, valtype::f64}, {valtype::f64}}); break;
        case f32copysign: apply({{valtype::f32, valtype::f32}, {valtype::f32}}); break;
        case f64copysign: apply({{valtype::f64, valtype::f64}, {valtype::f64}}); break;
        case i32wrap_i64:      apply({{valtype::i64}, {valtype::i32}}); break;
        case i64extend_i32_s:  apply({{valtype::i32}, {valtype::i64}}); break;
        case i64extend_i32_u:  apply({{valtype::i32}, {valtype::i64}}); break;
        case i32trunc_f32_s:   apply({{valtype::f32}, {valtype::i32}}); break;
        case i64trunc_f32_s:   apply({{valtype::f32}, {valtype::i64}}); break;
        case i32trunc_f32_u:   apply({{valtype::f32}, {valtype::i32}}); break;
        case i64trunc_f32_u:   apply({{valtype::f32}, {valtype::i64}}); break;
        case i32trunc_f64_s:   apply({{valtype::f64}, {valtype::i32}}); break;
        case i64trunc_f64_s:   apply({{valtype::f64}, {valtype::i64}}); break;
        case i32trunc_f64_u:   apply({{valtype::f64}, {valtype::i32}}); break;
        case i64trunc_f64_u:   apply({{valtype::f64}, {valtype::i64}}); break;
        case f32convert_i32_s: apply({{valtype::i32}, {valtype::f32}}); break;
        case f64convert_i32_s: apply({{valtype::i32}, {valtype::f64}}); break;
        case f32convert_i32_u: apply({{valtype::i32}, {valtype::f32}}); break;
        case f64convert_i32_u: apply({{valtype::i32}, {valtype::f64}}); break;
        case f32convert_i64_s: apply({{valtype::i64}, {valtype::f32}}); break;
        case f64convert_i64_s: apply({{valtype::i64}, {valtype::f64}}); break;
        case f32convert_i64_u: apply({{valtype::i64}, {valtype::f32}}); break;
        case f64convert_i64_u: apply({{valtype::i64}, {valtype::f64}}); break;
        case f32demote_f64:    apply({{valtype::f64}, {valtype::f32}}); break;
        case f64promote_f32:   apply({{valtype::f32}, {valtype::f64}}); break;
        case i32reinterpret_f32: apply({{valtype::f32}, {valtype::i32}}); break;
        case f32reinterpret_i32: apply({{valtype::i32}, {valtype::f32}}); break;
        case i64reinterpret_f64: apply({{valtype::f64}, {valtype::i64}}); break;
        case f64reinterpret_i64: apply({{valtype::i64}, {valtype::f64}}); break;
        case i32extend8_s:  apply({{valtype::i32}, {valtype::i32}}); break;
        case i32extend16_s: apply({{valtype::i32}, {valtype::i32}}); break;
        case i64extend8_s:  apply({{valtype::i64}, {valtype::i64}}); break;
        case i64extend16_s: apply({{valtype::i64}, {valtype::i64}}); break;
        case i64extend32_s: apply({{valtype::i64}, {valtype::i64}}); break;
        case ref_null: {
            uint32_t type_idx = safe_read_leb128<uint32_t>(iter);
            ensure(is_reftype(type_idx), "type mismatch");
            apply({{}, {static_cast<valtype>(type_idx)}});
            break;
        }
        case ref_is_null: {
            valtype peek = stack.back();
            ensure(peek == valtype::empty || is_reftype(peek), "type mismatch");
            apply({{peek}, {valtype::i32}});
            break;
        }
        case ref_func: {
            uint32_t func_idx = safe_read_leb128<uint32_t>(iter);
            ensure(func_idx < functions.size(), "invalid function index");
            ensure(functions[func_idx].is_declared, "undeclared function reference");
            apply({{}, {valtype::funcref}});
            break;
        }
        case ref_eq: {
            valtype peek = stack.back();
            ensure(peek == valtype::empty || is_reftype(peek), "type mismatch");
            apply({{peek, peek}, {valtype::i32}});
            break;
        }
        case multibyte: {
            uint32_t byte = safe_read_leb128<uint32_t>(iter);
#if WASM_DEBUG
            std::cerr << "reading multibyte instruction " << multibyte_instructions[byte].c_str()
                      << " at " << iter - bytes.get() << std::endl;
#endif

            using enum FCInstruction;
            switch (static_cast<FCInstruction>(byte)) {
                case i32_trunc_sat_f32_s:
                    apply({{valtype::f32}, {valtype::i32}});
                    break;
                case i32_trunc_sat_f32_u:
                    apply({{valtype::f32}, {valtype::i32}});
                    break;
                case i32_trunc_sat_f64_s:
                    apply({{valtype::f64}, {valtype::i32}});
                    break;
                case i32_trunc_sat_f64_u:
                    apply({{valtype::f64}, {valtype::i32}});
                    break;
                case i64_trunc_sat_f32_s:
                    apply({{valtype::f32}, {valtype::i64}});
                    break;
                case i64_trunc_sat_f32_u:
                    apply({{valtype::f32}, {valtype::i64}});
                    break;
                case i64_trunc_sat_f64_s:
                    apply({{valtype::f64}, {valtype::i64}});
                    break;
                case i64_trunc_sat_f64_u:
                    apply({{valtype::f64}, {valtype::i64}});
                    break;
                case memory_init: {
                    uint32_t seg_idx = safe_read_leb128<uint32_t>(iter);
                    if (*iter++ != 0) throw malformed_error("zero byte expected");

                    ensure(memory.exists, "unknown memory 0");
                    if (n_data == std::numeric_limits<uint32_t>::max()) {
                        throw malformed_error("data count section required");
                    }
                    ensure(seg_idx < n_data, "unknown data segment");

                    apply({{valtype::i32, valtype::i32, valtype::i32}, {}});
                    break;
                }
                case data_drop: {
                    uint32_t seg_idx = safe_read_leb128<uint32_t>(iter);
                    if (n_data == std::numeric_limits<uint32_t>::max()) {
                        throw malformed_error("data count section required");
                    }
                    ensure(seg_idx < n_data, "unknown data segment");
                    break;
                }
                case memory_copy: {
                    if (*iter++ != 0) throw malformed_error("zero byte expected");
                    if (*iter++ != 0) throw malformed_error("zero byte expected");
                    ensure(memory.exists, "unknown memory 0");

                    apply({{valtype::i32, valtype::i32, valtype::i32}, {}});
                    break;
                }
                case memory_fill: {
                    if (*iter++ != 0) throw malformed_error("zero byte expected");
                    ensure(memory.exists, "unknown memory 0");

                    apply({{valtype::i32, valtype::i32, valtype::i32}, {}});
                    break;
                }
                case table_init: {
                    uint32_t seg_idx = safe_read_leb128<uint32_t>(iter);
                    uint32_t table_idx = safe_read_leb128<uint32_t>(iter);

                    ensure(table_idx < tables.size(), "unknown table " + std::to_string(table_idx));
                    ensure(seg_idx < elements.size(), "unknown data segment");
                    ensure(tables[table_idx].type == elements[seg_idx].type, "type mismatch");

                    apply({{valtype::i32, valtype::i32, valtype::i32}, {}});
                    break;
                }
                case elem_drop: {
                    uint32_t seg_idx = safe_read_leb128<uint32_t>(iter);
                    ensure(seg_idx < elements.size(), "unknown elem segment " + std::to_string(seg_idx));
                    break;
                }
                case table_copy: {
                    uint32_t src_table_idx = safe_read_leb128<uint32_t>(iter);
                    ensure(src_table_idx < tables.size(), "unknown table");
                    uint32_t dst_table_idx = safe_read_leb128<uint32_t>(iter);
                    ensure(dst_table_idx < tables.size(), "unknown table");
                    ensure(tables[src_table_idx].type == tables[dst_table_idx].type, "type mismatch");

                    apply({{valtype::i32, valtype::i32, valtype::i32}, {}});
                    break;
                }
                case table_grow: {
                    uint32_t table_idx = safe_read_leb128<uint32_t>(iter);
                    ensure(table_idx < tables.size(), "unknown table");

                    apply({{tables[table_idx].type, valtype::i32}, {valtype::i32}});
                    break;
                }
                case table_size: {
                    uint32_t table_idx = safe_read_leb128<uint32_t>(iter);
                    ensure(table_idx < tables.size(), "unknown table");

                    apply({{}, {valtype::i32}});
                    break;
                }
                case table_fill: {
                    uint32_t table_idx = safe_read_leb128<uint32_t>(iter);
                    ensure(table_idx < tables.size(), "unknown table");

                    apply({{valtype::i32, tables[table_idx].type, valtype::i32}, {}});
                    break;
                }
                default: ensure(false, "unimplemented FC extension instruction " + std::to_string(byte));
            }
            break;
        }
        default: ensure(false, "unimplemented instruction " + std::to_string(byte));
            // clang-format on
        };
    }

    ensure(false, "unreachable");
}

#undef ensure

} // namespace mitey
