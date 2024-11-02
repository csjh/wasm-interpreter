#include "interpreter.hpp"
#include "spec.hpp"
#include "validator.hpp"
#include <algorithm>
#include <functional>
#include <iostream>
#include <limits>

#ifdef WASM_DEBUG
#include <iostream>
#endif

namespace mitey {
safe_byte_iterator::safe_byte_iterator(uint8_t *begin, uint8_t *end)
    : iter(begin), end(end) {}

uint8_t safe_byte_iterator::operator*() const {
    if (iter == end) {
        throw malformed_error("unexpected end");
    }
    return *iter;
}

uint8_t safe_byte_iterator::operator[](size_t n) const {
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
        throw malformed_error("unexpected end");
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

struct SignatureHasher {
    size_t operator()(const Signature &sig) const {
        size_t hash = 0;
        for (valtype param : sig.params) {
            hash ^= std::hash<uint8_t>{}(static_cast<uint8_t>(param));
        }
        for (valtype result : sig.results) {
            hash ^= std::hash<uint8_t>{}(static_cast<uint8_t>(result));
        }
        return hash;
    }
};

struct SignatureEquality {
    bool operator()(const Signature &lhs, const Signature &rhs) const {
        return lhs.params == rhs.params && lhs.results == rhs.results;
    }
};

std::tuple<uint32_t, uint32_t> get_limits(safe_byte_iterator &iter) {
    uint32_t flags = safe_read_leb128<uint32_t>(iter);
    if (flags != 0 && flags != 1) {
        throw validation_error("invalid flags");
    }
    uint32_t initial = safe_read_leb128<uint32_t>(iter);
    uint32_t maximum = flags == 1 ? safe_read_leb128<uint32_t>(iter)
                                  : std::numeric_limits<uint32_t>::max();
    if (maximum < initial) {
        throw validation_error("maximum is less than initial");
    }
    return {initial, maximum};
}

Instance::Instance(std::unique_ptr<uint8_t, void (*)(uint8_t *)> _bytes,
                   uint32_t length, const Imports &imports)
    : bytes(std::move(_bytes)),
      stack(static_cast<WasmValue *>(malloc(stack_size))), stack_start(stack) {

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
                throw malformed_error("invalid UTF-8 encoding");
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
                throw malformed_error("unexpected end of section or function");
            }
            safe_byte_iterator section_start = iter;

            body();

            if (iter - section_start != section_length) {
                throw malformed_error("section size mismatch");
            }
        } else {
            else_();
        }
    };

    skip_custom_section();

    // type section
    section(1, [&] {
        std::unordered_map<Signature, uint32_t, SignatureHasher,
                           SignatureEquality>
            deduplicator;

        uint32_t n_types = safe_read_leb128<uint32_t>(iter);

        types.reserve(n_types);

        for (uint32_t i = 0; i < n_types; ++i) {
            if (iter.empty()) {
                throw malformed_error("unexpected end of section or function");
            }

            if (*iter != 0x60) {
                throw validation_error("invalid function type");
            }
            ++iter;

            Signature fn{{}, {}, i};

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
            // todo: change this with multivalue proposal
            if (n_results > 1) {
                throw validation_error("invalid result arity");
            }
            fn.results.reserve(n_results);
            for (uint32_t j = 0; j < n_results; ++j) {
                if (!is_valtype(iter[j])) {
                    throw validation_error("invalid result type");
                }
                fn.results.push_back(static_cast<valtype>(iter[j]));
            }
            iter += n_results;

            if (deduplicator.contains(fn)) {
                fn.typeidx = deduplicator[fn];
            } else {
                deduplicator[fn] = fn.typeidx;
            }

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
                throw malformed_error("invalid UTF-8 encoding");
            }
            std::string module(
                reinterpret_cast<char *>(iter.get_with_at_least(module_len)),
                module_len);
            if (!imports.contains(module)) {
                throw validation_error("unknown import");
            }
            const auto &module_imports = imports.at(module);
            iter += module_len;

            uint32_t field_len = safe_read_leb128<uint32_t>(iter);
            if (!is_valid_utf8(iter.get_with_at_least(field_len),
                               (iter + field_len).unsafe_ptr())) {
                throw malformed_error("invalid UTF-8 encoding");
            }
            std::string field(
                reinterpret_cast<char *>(iter.get_with_at_least(field_len)),
                field_len);
            iter += field_len;
            if (!module_imports.contains(field)) {
                throw validation_error("unknown import");
            }
            const auto &import = module_imports.at(field);

            uint32_t kind = safe_read_leb128<uint32_t>(iter);
            if (kind != import.index()) {
                throw validation_error("incompatible import type");
            }
            if (std::holds_alternative<FunctionInfo>(import)) {
                // func
                uint32_t typeidx = safe_read_leb128<uint32_t>(iter);
                if (typeidx >= types.size()) {
                    throw validation_error("unknown type");
                }

                auto fn = std::get<FunctionInfo>(import);
                if (!SignatureEquality().operator()(types[typeidx], fn.type)) {
                    throw validation_error("incompatible function type");
                }
                fn.type = types[typeidx];

                functions.push_back(fn);
                n_fn_imports++;
            } else if (std::holds_alternative<std::shared_ptr<WasmTable>>(
                           import)) {
                // table
                uint32_t reftype = safe_read_leb128<uint32_t>(iter);
                if (!is_reftype(reftype)) {
                    throw validation_error("invalid reftype");
                }

                auto table = std::get<std::shared_ptr<WasmTable>>(import);
                auto [initial, max] = get_limits(iter);
                if (table->size() < initial) {
                    throw validation_error("table size exceeds limit");
                }
                if (table->max() > max) {
                    throw validation_error("table size exceeds limit");
                }
                tables.push_back(table);
            } else if (std::holds_alternative<std::shared_ptr<WasmMemory>>(
                           import)) {
                // mem
                if (memory) {
                    throw validation_error("multiple memories");
                }

                auto [initial, max] = get_limits(iter);
                auto memory = std::get<std::shared_ptr<WasmMemory>>(import);
                if (memory->size() < initial) {
                    throw validation_error("memory size exceeds limit");
                }
                if (memory->max() > max) {
                    throw validation_error("memory size exceeds limit");
                }
                this->memory = memory;
            } else if (std::holds_alternative<std::shared_ptr<WasmGlobal>>(
                           import)) {
                // global
                uint32_t valtype = safe_read_leb128<uint32_t>(iter);
                if (!is_valtype(valtype) && !is_reftype(valtype)) {
                    throw malformed_error("invalid global type");
                }
                uint8_t mut = *iter++;
                if (!is_mut(mut)) {
                    throw malformed_error("invalid mutability");
                }

                auto global = std::get<std::shared_ptr<WasmGlobal>>(import);
                if (global->_mut != static_cast<enum mut>(mut) ||
                    global->type != static_cast<enum valtype>(valtype)) {
                    throw validation_error("incompatible global type");
                }

                globals.push_back(global);
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
            functions.emplace_back(FunctionInfo{nullptr, types[type_idx], {}});
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

            auto [initial, maximum] = get_limits(iter);
            tables.emplace_back(std::make_shared<WasmTable>(
                static_cast<valtype>(elem_type), initial, maximum));
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
            if (memory) {
                throw validation_error("multiple memories");
            }

            auto [initial, maximum] = get_limits(iter);
            memory = std::make_shared<WasmMemory>(initial, maximum);
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
                throw malformed_error("invalid mutability");
            }
            mut global_mut = static_cast<mut>(maybe_mut);

            globals.push_back(std::make_shared<WasmGlobal>(
                type, global_mut, interpret_const(iter, type)));
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
            if (desc < 0 || desc > 3) {
                throw validation_error("invalid export description");
            }
            ExportDesc export_desc = static_cast<ExportDesc>(desc);

            uint32_t idx = safe_read_leb128<uint32_t>(iter);

            if (exports.contains(name)) {
                throw validation_error("duplicate export name");
            }

            if (export_desc == ExportDesc::func) {
                if (idx >= functions.size()) {
                    throw validation_error("invalid function index");
                }
                const auto &fn = functions[idx];
                if (fn.start != nullptr) {
                    exports[name] = FunctionInfo(
                        [&] {
                            call_function_info(fn, nullptr,
                                               [&] { interpret(fn.start); });
                        },
                        fn.type);
                } else {
                    exports[name] = fn;
                }
            } else if (export_desc == ExportDesc::table) {
                if (idx >= tables.size()) {
                    throw validation_error("invalid table index");
                }
                exports[name] = tables[idx];
            } else if (export_desc == ExportDesc::mem) {
                if (!memory) {
                    throw validation_error("no memory to export");
                }
                exports[name] = memory;
            } else if (export_desc == ExportDesc::global) {
                if (idx >= globals.size()) {
                    throw validation_error("invalid global index");
                }
                exports[name] = globals[idx];
            }
        }
    });

    skip_custom_section();

    // start section
    uint32_t start = std::numeric_limits<uint32_t>::max();
    section(8, [&] {
        start = safe_read_leb128<uint32_t>(iter);
        if (start >= functions.size()) {
            throw validation_error("invalid start function");
        }
    });

    skip_custom_section();

    // element section
    section(9, [&] {
        uint32_t n_elements = safe_read_leb128<uint32_t>(iter);

        elements.reserve(n_elements);

        for (uint32_t i = 0; i < n_elements; i++) {
            /*
            why is this not needed
            if (iter.empty()) {
                throw malformed_error("unexpected end of section or function");
            }
            */
            uint32_t flags = safe_read_leb128<uint32_t>(iter);
            if (flags & ~0b111) {
                throw validation_error("invalid element flags");
            }

            if (flags & 1) {
                if (flags & 0b10) {
                    // i don't know what declarative is for but i have to skip
                    // the bytes somehow
                    if (flags & 0b100) {
                        // flags = 7
                        // characteristics: declarative, elem type + exprs
                        uint32_t reftype = *iter++;
                        if (!is_reftype(reftype)) {
                            throw validation_error("invalid reftype");
                        }
                        uint32_t n_elements = safe_read_leb128<uint32_t>(iter);
                        for (uint32_t j = 0; j < n_elements; j++) {
                            interpret_const(iter,
                                            static_cast<valtype>(reftype));
                        }
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
                                throw validation_error("invalid element index");
                            }
                        }
                    }
                } else {
                    if (flags & 0b100) {
                        // flags = 5
                        // characteristics: passive, elem type + exprs
                        uint8_t reftype = *iter++;
                        if (!is_reftype(reftype)) {
                            throw validation_error("invalid reftype");
                        }
                        uint32_t n_elements = safe_read_leb128<uint32_t>(iter);
                        std::vector<WasmValue> elem{n_elements};
                        for (uint32_t j = 0; j < n_elements; j++) {
                            WasmValue el = interpret_const(
                                iter, static_cast<valtype>(reftype));
                            elem.push_back(el);
                        }
                        elements.emplace_back(elem);
                    } else {
                        // flags = 1
                        // characteristics: passive, elem kind + indices
                        uint8_t elemkind = *iter++;
                        if (elemkind != 0) {
                            throw validation_error("invalid elemkind");
                        }
                        uint32_t n_elements = safe_read_leb128<uint32_t>(iter);
                        std::vector<WasmValue> elem{n_elements};
                        for (uint32_t j = 0; j < n_elements; j++) {
                            uint32_t elem_idx =
                                safe_read_leb128<uint32_t>(iter);
                            if (elem_idx >= functions.size()) {
                                throw validation_error("invalid element index");
                            }
                            elem.push_back(
                                Funcref{functions[elem_idx].type.typeidx, true,
                                        elem_idx});
                        }
                        elements.emplace_back(elem);
                    }
                }
            } else {
                uint32_t table_idx =
                    flags & 0b10 ? safe_read_leb128<uint32_t>(iter) : 0;

                uint32_t offset = interpret_const(iter, valtype::i32).u32;
                uint32_t n_elements = safe_read_leb128<uint32_t>(iter);
                if (offset + n_elements > tables[table_idx]->size()) {
                    throw validation_error("invalid table offset");
                }

                std::vector<WasmValue> elem{n_elements};
                if (flags & 0b100) {
                    // flags = 4 or 6
                    // characteristics: active, elem type + exprs
                    uint8_t reftype =
                        flags & 0b10 ? *iter++
                                     : static_cast<uint8_t>(valtype::funcref);
                    if (!is_reftype(reftype)) {
                        throw validation_error("invalid reftype");
                    }
                    for (uint32_t j = 0; j < n_elements; j++) {
                        WasmValue el = interpret_const(
                            iter, static_cast<valtype>(reftype));
                        elem.push_back(el);
                        tables[table_idx]->set(offset + j, el);
                    }
                } else {
                    if (flags & 0b10) {
                        uint8_t elemkind = *iter++;
                        if (elemkind != 0) {
                            throw validation_error("invalid elemkind");
                        }
                    }
                    // flags = 0 or 2
                    // characteristics: active, elem kind + indices
                    for (uint32_t j = 0; j < n_elements; j++) {
                        uint32_t elem_idx = safe_read_leb128<uint32_t>(iter);
                        if (elem_idx >= functions.size()) {
                            throw validation_error("invalid element index");
                        }
                        WasmValue funcref = Funcref{
                            functions[elem_idx].type.typeidx, true, elem_idx};
                        elem.push_back(funcref);
                        tables[table_idx]->set(offset + j, funcref);
                    }
                }
                elements.emplace_back(elem);
            }
        }
    });

    skip_custom_section();

    // data count section
    section(12, [&] {
        ++iter;
        uint32_t section_length = safe_read_leb128<uint32_t>(iter);
        if (!iter.has_n_left(section_length)) {
            throw malformed_error("unexpected end of section or function");
        }

        iter += section_length;
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

            for (FunctionInfo &fn : functions) {
                fn.locals = fn.type.params;

                uint32_t function_length = safe_read_leb128<uint32_t>(iter);

                safe_byte_iterator start = iter;

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
                fn.start =
                    iter.get_with_at_least(function_length - (iter - start));

                iter = start + function_length;
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
    section(11, [&] {
        uint32_t n_data = safe_read_leb128<uint32_t>(iter);

        for (uint32_t i = 0; i < n_data; i++) {
            if (iter.empty()) {
                throw malformed_error("unexpected end of section or function");
            }

            uint32_t segment_flag = safe_read_leb128<uint32_t>(iter);
            if (segment_flag & ~0b11) {
                throw validation_error("invalid data segment flag");
            }

            uint32_t memidx =
                segment_flag & 0b10 ? safe_read_leb128<uint32_t>(iter) : 0;

            if (memidx != 0) {
                throw validation_error("non-zero memory index");
            }

            if (segment_flag & 1) {
                // passive segment

                uint32_t data_length = safe_read_leb128<uint32_t>(iter);
                if (!iter.has_n_left(data_length)) {
                    throw malformed_error(
                        "unexpected end of section or function");
                }
                std::vector<uint8_t> data(data_length);
                std::memcpy(data.data(), iter.get_with_at_least(data_length),
                            data_length);
                iter += data_length;

                data_segments.emplace_back(Segment{memidx, std::move(data)});
            } else {
                // active segment

                uint32_t offset = interpret_const(iter, valtype::i32).u32;
                uint32_t data_length = safe_read_leb128<uint32_t>(iter);

                if (offset + data_length >
                    memory->size() * WasmMemory::PAGE_SIZE) {
                    throw validation_error("invalid memory offset");
                }
                if (!iter.has_n_left(data_length)) {
                    throw malformed_error(
                        "unexpected end of section or function");
                }

                std::vector<uint8_t> data(data_length);
                std::memcpy(data.data(), iter.get_with_at_least(data_length),
                            data_length);
                iter += data_length;

                memory->copy_into(offset, data.data(), data_length);

                data_segments.emplace_back(Segment{memidx, std::move(data)});
            }
        }
    });

    skip_custom_section();

    if (!iter.empty()) {
        throw malformed_error("invalid section id");
    }

    Validator(*this).validate(bytes.get() + length);

    if (start != std::numeric_limits<uint32_t>::max()) {
        const auto &fn = functions[start];
        if (fn.type.params.size() || fn.type.results.size()) {
            throw validation_error(
                "start function must have no params or results");
        }
        try {
            call_function_info(fn, nullptr, [&] { interpret(fn.start); });
        } catch (const trap_error &) {
            throw validation_error("start function trapped");
        }
    }
}

inline void Instance::call_function_info(const FunctionInfo &fn,
                                         uint8_t *return_to,
                                         std::function<void()> wasm_call) {
    if (fn.start != nullptr) {
        // parameters are the first locals and they're taken from the top of
        // the stack
        WasmValue *locals_start = stack - fn.type.params.size();
        WasmValue *locals_end = locals_start + fn.locals.size();
        // zero out non-parameter locals
        std::memset(stack, 0, (locals_end - stack) * sizeof(WasmValue));
        stack = locals_end;
        frames.emplace_back(
            StackFrame{locals_start,
                       {{locals_start, return_to,
                         static_cast<uint32_t>(fn.type.results.size())}}});

#if WASM_DEBUG
        constexpr size_t MAX_DEPTH = 1'000;
#else
        constexpr size_t MAX_DEPTH = 1'000'000;
#endif
        if (frames.size() > MAX_DEPTH) {
            trap("call stack exhausted");
        }

        wasm_call();
    } else {
        stack -= fn.type.params.size();
        if (fn.static_fn != nullptr) {
            fn.static_fn(stack);
        } else {
            fn.dyn_fn(stack);
        }
        stack += fn.type.results.size();
    }
}

// constant expressions (including extended const expression proposal)
// this shoves validation and execution into one for simplicity(?)
WasmValue Instance::interpret_const(safe_byte_iterator &iter,
                                    valtype expected) {
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
        stack--;                                                               \
        stack[-1].ty = stack[-1].ty op stack[0].ty;                            \
        break;                                                                 \
    }
#define I32_OP(op) OP(i32, op)
#define I64_OP(op) OP(i64, op)

    while (1) {
        uint8_t byte = *iter++;
#ifdef WASM_DEBUG
        std::cerr << "reading const instruction " << instructions[byte].c_str()
                  << " at " << iter - bytes.get() << std::endl;
        std::cerr << "stack contents: ";
        for (WasmValue *p = stack_start; p < stack; ++p) {
            std::cerr << p->u64 << " ";
        }
        std::cerr << std::endl << std::endl;
#endif
        using enum Instruction;
        if (static_cast<Instruction>(byte) == end) {
            break;
        }
        switch (static_cast<Instruction>(byte)) {
        case i32const:
            *stack++ = safe_read_sleb128<int32_t>(iter);
            stack_types.push_back(valtype::i32);
            break;
        case i64const:
            *stack++ = safe_read_sleb128<int64_t>(iter);
            stack_types.push_back(valtype::i64);
            break;
        case f32const:
            *stack++ = *reinterpret_cast<float *>(
                iter.get_with_at_least(sizeof(float)));
            iter += sizeof(float);
            stack_types.push_back(valtype::f32);
            break;
        case f64const:
            *stack++ = *reinterpret_cast<double *>(
                iter.get_with_at_least(sizeof(double)));
            iter += sizeof(double);
            stack_types.push_back(valtype::f64);
            break;
        case globalget: {
            uint32_t global_idx = safe_read_leb128<uint32_t>(iter);
            if (global_idx >= globals.size()) {
                throw validation_error("unknown global");
            }
            *stack++ = globals[global_idx]->value;
            stack_types.push_back(globals[global_idx]->type);
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
            *stack++ = nullptr;
            uint32_t reftype = safe_read_leb128<uint32_t>(iter);
            if (!is_reftype(reftype)) {
                throw validation_error("invalid reference type");
            }
            stack_types.push_back(static_cast<valtype>(reftype));
            break;
        }
        case ref_func: {
            uint32_t func_idx = safe_read_leb128<uint32_t>(iter);
            if (func_idx >= functions.size()) {
                throw validation_error("unknown function");
            }
            *stack++ =
                Funcref{functions[func_idx].type.typeidx, true, func_idx};
            stack_types.push_back(valtype::funcref);
            break;
        }
        default:
            throw validation_error("constant expression required");
        }
    }

#undef OP
#undef I32_OP
#undef I64_OP

    if (stack - stack_start != 1 || stack_types.size() != 1 ||
        stack_types[0] != expected) {
        throw validation_error("type mismatch");
    }

#ifdef WASM_DEBUG
    std::cerr << "const expression result: " << stack[-1].u64 << std::endl;
#endif

    return *--stack;
}

void Instance::interpret(uint8_t *iter) {
    auto push = [&](WasmValue value) { *stack++ = value; };
    auto pop = [&]() { return *--stack; };

    using i32 = int32_t;
    using u32 = uint32_t;
    using i64 = int64_t;
    using u64 = uint64_t;
    using f32 = float;
    using f64 = double;

    /*
        (functions and ifs are blocks)

        enter into loop          -> valid if stack <= param_type
        enter into block         -> valid if stack <= param_type
        br depth is loop (enter) -> valid if stack <= param_type
        br depth is block (exit) -> valid if stack <= return_type
        exit from loop           -> valid if stack == return_type
        exit from block          -> valid if stack == return_type
    */
    auto brk = [&](uint32_t depth) {
        depth++;
        std::vector<BrTarget> &control_stack = frame().control_stack;
        BrTarget target = control_stack[control_stack.size() - depth];
        control_stack.erase(control_stack.end() - depth, control_stack.end());
        std::memmove(target.stack, stack - target.arity,
                     target.arity * sizeof(WasmValue));
        stack = target.stack + target.arity;
        iter = target.dest;
        if (control_stack.empty()) {
            frames.pop_back();
            return frames.empty();
        } else {
            return false;
        }
    };

#define UNARY_OP(type, op)                                                     \
    stack[-1] = op(stack[-1].type);                                            \
    break
#define TRUNC(type, op, lower, upper)                                          \
    {                                                                          \
        if (!std::isfinite(stack[-1].type)) {                                  \
            if (isnan(stack[-1].type)) {                                       \
                trap("invalid conversion to integer");                         \
            } else {                                                           \
                trap("integer overflow");                                      \
            }                                                                  \
        }                                                                      \
        if (stack[-1].type <= lower || upper <= stack[-1].type) {              \
            trap("integer overflow");                                          \
        }                                                                      \
        UNARY_OP(type, op);                                                    \
    }
#define UNARY_FN(type, fn)                                                     \
    stack[-1] = fn(stack[-1].type);                                            \
    break
#define BINARY_OP(type, op)                                                    \
    {                                                                          \
        stack--;                                                               \
        stack[-1] = stack[-1].type op stack[0].type;                           \
        break;                                                                 \
    }
#define BINARY_FN(type, fn)                                                    \
    {                                                                          \
        stack--;                                                               \
        stack[-1] = fn(stack[-1].type, stack[0].type);                         \
        break;                                                                 \
    }
#define IDIV(type)                                                             \
    {                                                                          \
        stack--;                                                               \
        if (stack[0].type == 0) {                                              \
            trap("integer divide by zero");                                    \
        }                                                                      \
        if (std::is_signed_v<type> &&                                          \
            stack[0].type == static_cast<type>(-1) &&                          \
            stack[-1].type == std::numeric_limits<type>::min()) {              \
            trap("integer overflow");                                          \
        }                                                                      \
        stack[-1] = stack[-1].type / stack[0].type;                            \
        break;                                                                 \
    }
#define IREM(type)                                                             \
    {                                                                          \
        stack--;                                                               \
        if (stack[0].type == 0) {                                              \
            trap("integer divide by zero");                                    \
        }                                                                      \
        stack[-1] = stack[-1].type % stack[0].type;                            \
        break;                                                                 \
    }
#define MINMAX(type, fn)                                                       \
    {                                                                          \
        stack--;                                                               \
        if (isnan(stack[-1].type) || isnan(stack[0].type)) {                   \
            stack[-1].type = std::numeric_limits<type>::quiet_NaN();           \
        } else {                                                               \
            stack[-1].type = fn(stack[-1].type, stack[0].type);                \
        }                                                                      \
        break;                                                                 \
    }
#define SHIFT(type, op)                                                        \
    {                                                                          \
        stack--;                                                               \
        stack[-1] = stack[-1].type op(stack[0].type % (sizeof(type) * 8));     \
        break;                                                                 \
    }

#define LOAD(type, memtype)                                                    \
    {                                                                          \
        uint32_t align = 1 << *iter++;                                         \
        uint32_t offset = read_leb128(iter);                                   \
        stack[-1].type = memory->load<memtype>(stack[-1].u32, offset, align);  \
        break;                                                                 \
    }

#define STORE(type, stacktype)                                                 \
    {                                                                          \
        stack -= 2;                                                            \
        uint32_t align = 1 << *iter++;                                         \
        uint32_t offset = read_leb128(iter);                                   \
        memory->store<type>(stack[0].u32, offset, align,                       \
                            static_cast<type>(stack[1].stacktype));            \
        break;                                                                 \
    }

    using enum Instruction;

    while (1) {
        uint8_t byte = *iter++;
#ifdef WASM_DEBUG
        std::cerr << "reading instruction " << instructions[byte].c_str()
                  << " at " << iter - bytes.get() << std::endl;
        std::cerr << "stack contents: ";
        for (WasmValue *p = stack_start; p < stack; ++p) {
            std::cerr << p->u64 << " ";
        }
        std::cerr << std::endl << std::endl;
#endif
        switch (static_cast<Instruction>(byte)) {
        case unreachable:
            trap("unreachable");
            break;
        case nop:
            break;
        case block: {
            Signature sn = read_blocktype(iter);
            frame().control_stack.push_back(
                {stack - sn.params.size(), block_ends[iter],
                 static_cast<uint32_t>(sn.results.size())});
            break;
        }
        case loop: {
            // reading blocktype each time maybe not efficient?
            uint8_t *loop_start = iter - 1;
            Signature sn = read_blocktype(iter);
            frame().control_stack.push_back(
                // iter - 1 so br goes back to the loop
                {stack - sn.params.size(), loop_start,
                 static_cast<uint32_t>(sn.params.size())});
            break;
        }
        case if_: {
            Signature sn = read_blocktype(iter);
            uint32_t cond = pop().u32;
            frame().control_stack.push_back(
                {stack - sn.params.size(), if_jumps[iter].end,
                 static_cast<uint32_t>(sn.results.size())});
            if (!cond)
                iter = if_jumps[iter].else_;
            break;
        }
        case else_:
            // if the else block is reached, the if block is done
            // might be faster to have another dictionary for else block -> end
            // so this can just be iter = end_block
            // todo: look at what compiler optimizes to
            brk(0);
            break;
        case end:
            if (frame().control_stack.size() == 1) {
                // function end block
                if (brk(0))
                    return;
            } else {
                // we don't know if this is a block or loop
                // so can't do brk(0)
                // BUT validation has confirmed that the result is
                // the only thing left on the stack, so we can just
                // pop the control stack (since the result is already in place)
                frame().control_stack.pop_back();
            }
            break;
        case br: {
            if (brk(read_leb128(iter)))
                return;
            break;
        }
        case br_if: {
            uint32_t depth = read_leb128(iter);
            if (pop().u32)
                if (brk(depth))
                    return;
            break;
        }
        case br_table: {
            uint32_t v = pop().u32;
            uint32_t n_targets = read_leb128(iter);
            uint32_t target, depth = std::numeric_limits<uint32_t>::max();

            // <= because there's an extra for the default target
            for (uint32_t i = 0; i <= n_targets; ++i) {
                target = read_leb128(iter);
                if (i == v)
                    depth = target;
            }
            // use default
            if (depth == std::numeric_limits<uint32_t>::max())
                depth = target;
            if (brk(depth))
                return;
            break;
        }
        case return_:
            brk(frame().control_stack.size() - 1);
            return;
        case call: {
            FunctionInfo &fn = functions[read_leb128(iter)];
            call_function_info(fn, iter, [&] { iter = fn.start; });
            break;
        }
        case call_indirect: {
            uint32_t type_idx = read_leb128(iter);
            uint32_t table_idx = read_leb128(iter);
            uint32_t elem_idx = pop().u32;

            Funcref funcref = tables[table_idx]->get(elem_idx);
            if (!funcref.nonnull) {
                trap("indirect call to null");
            }
            if (funcref.typeidx != types[type_idx].typeidx) {
                trap("indirect call type mismatch");
            }
            FunctionInfo &fn = functions[funcref.funcidx];
            call_function_info(fn, iter, [&] { iter = fn.start; });
            break;
        }
        case drop:
            stack--;
            break;
        case select: {
            stack -= 2;
            if (!stack[1].i32)
                stack[-1] = stack[0];
            break;
        }
        case localget:
            push(frame().locals[read_leb128(iter)]);
            break;
        case localset:
            frame().locals[read_leb128(iter)] = pop();
            break;
        case localtee:
            frame().locals[read_leb128(iter)] = stack[-1];
            break;
        case tableget:
            push(tables[read_leb128(iter)]->get(pop().u32));
            break;
        case tableset:
            tables[read_leb128(iter)]->set(pop().u32, pop());
            break;
        case globalget:
            push(globals[read_leb128(iter)]->value);
            break;
        case globalset:
            globals[read_leb128(iter)]->value = pop();
            break;
        case memorysize: {
            /* uint32_t mem_idx = */ read_leb128(iter);
            push(memory->size());
            break;
        }
        case memorygrow: {
            /* uint32_t mem_idx = */ read_leb128(iter);
            stack[-1].u32 = memory->grow(stack[-1].u32);
            break;
        }
        case i32const:
            push((int32_t)read_sleb128<32>(iter));
            break;
        case i64const:
            push((int64_t)read_sleb128<64>(iter));
            break;
        case f32const: {
            std::memcpy(&stack->f32, iter, sizeof(float));
            stack++;
            iter += sizeof(float);
            break;
        }
        case f64const:
            std::memcpy(&stack->f64, iter, sizeof(double));
            stack++;
            iter += sizeof(double);
            break;
        // clang-format off
        case i32load:      LOAD(u32, uint32_t);
        case i64load:      LOAD(u64, uint64_t);
        case f32load:      LOAD(f32, float);
        case f64load:      LOAD(f64, double);
        case i32load8_s:   LOAD(i32, int8_t);
        case i32load8_u:   LOAD(u32, uint8_t);
        case i32load16_s:  LOAD(i32, int16_t);
        case i32load16_u:  LOAD(u32, uint16_t);
        case i64load8_s:   LOAD(i64, int8_t);
        case i64load8_u:   LOAD(u64, uint8_t);
        case i64load16_s:  LOAD(i64, int16_t);
        case i64load16_u:  LOAD(u64, uint16_t);
        case i64load32_s:  LOAD(i64, int32_t);
        case i64load32_u:  LOAD(u64, uint32_t);
        case i32store:     STORE(uint32_t, u32);
        case i64store:     STORE(uint64_t, u64);
        case f32store:     STORE(float, f32);
        case f64store:     STORE(double, f64);
        case i32store8:    STORE(uint8_t, u32);
        case i32store16:   STORE(uint16_t, u32);
        case i64store8:    STORE(uint8_t, u64);
        case i64store16:   STORE(uint16_t, u64);
        case i64store32:   STORE(uint32_t, u64);
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
        case i32div_s:     IDIV     (i32);
        case i64div_s:     IDIV     (i64);
        case i32div_u:     IDIV     (u32);
        case i64div_u:     IDIV     (u64);
        case i32rem_s:     IREM     (i32);
        case i64rem_s:     IREM     (i64);
        case i32rem_u:     IREM     (u32);
        case i64rem_u:     IREM     (u64);
        case i32and:       BINARY_OP(u32, & );
        case i64and:       BINARY_OP(u64, & );
        case i32or:        BINARY_OP(u32, | );
        case i64or:        BINARY_OP(u64, | );
        case i32xor:       BINARY_OP(u32, ^ );
        case i64xor:       BINARY_OP(u64, ^ );
        case i32shl:       SHIFT    (u32, <<);
        case i64shl:       SHIFT    (u64, <<);
        case i32shr_s:     SHIFT    (i32, >>);
        case i64shr_s:     SHIFT    (i64, >>);
        case i32shr_u:     SHIFT    (u32, >>);
        case i64shr_u:     SHIFT    (u64, >>);
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
        case f32min:       MINMAX   (f32, std::min);
        case f64min:       MINMAX   (f64, std::min);
        case f32max:       MINMAX   (f32, std::max);
        case f64max:       MINMAX   (f64, std::max);
        case f32copysign:  BINARY_FN(f32, std::copysign);
        case f64copysign:  BINARY_FN(f64, std::copysign);
        case i32wrap_i64:      UNARY_OP(i64, (int32_t));
        case i64extend_i32_s:  UNARY_OP(i32, (int64_t));
        case i64extend_i32_u:  UNARY_OP(u32, (uint64_t));
        case i32trunc_f32_s:   TRUNC   (f32, (int32_t),           -2147483777.,           2147483648.);
        case i64trunc_f32_s:   TRUNC   (f32, (int64_t),  -9223373136366404000.,  9223372036854776000.);
        case i32trunc_f32_u:   TRUNC   (f32, (uint32_t),                   -1.,           4294967296.);
        case i64trunc_f32_u:   TRUNC   (f32, (uint64_t),                   -1., 18446744073709552000.);
        case i32trunc_f64_s:   TRUNC   (f64, (int32_t),           -2147483649.,           2147483648.);
        case i64trunc_f64_s:   TRUNC   (f64, (int64_t),  -9223372036854777856.,  9223372036854776000.);
        case i32trunc_f64_u:   TRUNC   (f64, (uint32_t),                   -1.,           4294967296.);
        case i64trunc_f64_u:   TRUNC   (f64, (uint64_t),                   -1., 18446744073709552000.);
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
        case ref_null: {
            read_leb128(iter);
            push(nullptr);
            break;
        }
        case ref_is_null: {
            // note that funcref is also a full 0 value when null
            stack[-1].i32 = stack[-1].externref == nullptr;
            break;
        }
        case ref_func: {
            uint32_t func_idx = read_leb128(iter);
            if (func_idx >= functions.size()) {
                trap("invalid function index");
            }
            push(Funcref{functions[func_idx].type.typeidx, true, func_idx});
            break;
        }
        // bitwise comparison applies to both
        case ref_eq: BINARY_OP(externref, ==);
        case multibyte: {
            byte = *iter++;
#if WASM_DEBUG
            std::cerr << "reading multibyte instruction " << instructions[byte].c_str()
                      << " at " << iter - bytes.get() << std::endl;
#endif
            using enum FCInstruction;

            switch (static_cast<FCInstruction>(byte)) {
                case memory_init: {
                    uint32_t seg_idx = read_leb128(iter);
                    uint32_t size = pop().u32;
                    uint32_t offset = pop().u32;
                    uint32_t dest = pop().u32;
                    if (dest + size > memory->size() * WasmMemory::PAGE_SIZE) {
                        trap("out of bounds memory access");
                    }
                    if (offset + size > data_segments[seg_idx].data.size()) {
                        trap("offset outside of data segment");
                    }
                    memory->copy_into(dest, data_segments[seg_idx].data.data() + offset, size);
                    break;
                }
                case data_drop: {
                    uint32_t seg_idx = read_leb128(iter);
                    data_segments[seg_idx].data.clear();
                    break;
                }
                case memory_copy: {
                    uint32_t src = pop().u32;
                    uint32_t dst = pop().u32;
                    uint32_t size = pop().u32;
                    memory->memcpy(dst, src, size);
                    break;
                }
                case memory_fill: {
                    uint32_t value = pop().u32;
                    uint32_t ptr = pop().u32;
                    uint32_t size = pop().u32;
                    memory->memset(ptr, value, size);
                    break;
                }
                case table_init: {
                    uint32_t table_idx = read_leb128(iter);
                    uint32_t seg_idx = read_leb128(iter);
                    uint32_t size = pop().u32;
                    uint32_t offset = pop().u32;
                    uint32_t dest = pop().u32;

                    auto& table = tables[table_idx];
                    if (dest + size > table->size()) {
                        trap("out of bounds memory access");
                    }

                    std::vector<WasmValue>& element = elements[seg_idx];
                    if (offset + size > element.size()) {
                        trap("offset outside of data segment");
                    }

                    table->copy_into(dest, element.data() + offset, size);
                    break;
                }
                case elem_drop: {
                    uint32_t seg_idx = read_leb128(iter);
                    elements[seg_idx].clear();
                    break;
                }
                case table_copy: {
                    uint32_t src = pop().u32;
                    uint32_t dst = pop().u32;
                    uint32_t size = pop().u32;
                    tables[dst]->memcpy(dst, src, size);
                    break;
                }
                case table_grow: {
                    uint32_t table_idx = read_leb128(iter);
                    WasmValue init = pop();
                    uint32_t delta = pop().u32;
                    stack[-1].u32 = tables[table_idx]->grow(delta, init);
                    break;
                }
                case table_size: {
                    uint32_t table_idx = read_leb128(iter);
                    push(tables[table_idx]->size());
                    break;
                }
                case table_fill: {
                    WasmValue value = pop();
                    uint32_t ptr = pop().u32;
                    uint32_t size = pop().u32;
                    uint32_t table_idx = read_leb128(iter);
                    tables[table_idx]->memset(ptr, value, size);
                    break;
                }
            }
        }
        default: __builtin_unreachable();
            // clang-format on
        };
    }

#undef UNARY_OP
#undef UNARY_FN
#undef BINARY_OP
#undef BINARY_FN
#undef LOAD
#undef STORE
}

// todo: this should check stack is the base pointer
// won't be necessary after validation is added
Instance::~Instance() {
    assert(stack == stack_start);
    free(stack_start);
}

WasmMemory::WasmMemory() : memory(nullptr), current(0), maximum(0) {}

WasmMemory::WasmMemory(uint32_t initial, uint32_t maximum)
    : memory(
          static_cast<uint8_t *>(calloc(initial * PAGE_SIZE, sizeof(uint8_t)))),
      current(initial), maximum(std::min(maximum, MAX_PAGES)) {}

WasmMemory::~WasmMemory() {
    if (memory) {
        free(memory);
    }
}

uint32_t WasmMemory::grow(uint32_t delta) {
    if (delta == 0)
        return current;
    uint32_t new_current = current + delta;
    if (new_current > maximum) {
        return -1;
    }

    uint8_t *new_memory = (uint8_t *)realloc(memory, new_current * PAGE_SIZE);
    if (new_memory == NULL)
        return -1;
    memory = new_memory;
    std::memset(memory + current * PAGE_SIZE, 0, delta * PAGE_SIZE);

    uint32_t old_current = current;
    current = new_current;
    return old_current;
}

void WasmMemory::copy_into(uint32_t ptr, const uint8_t *data, uint32_t length) {
    if (ptr + length > current * PAGE_SIZE) {
        trap("out of bounds memory access");
    }
    std::memcpy(memory + ptr, data, length);
}

void WasmMemory::memcpy(uint32_t dst, uint32_t src, uint32_t length) {
    if (dst + length > current * PAGE_SIZE ||
        src + length > current * PAGE_SIZE) {
        trap("out of bounds memory access");
    }
    std::memmove(memory + dst, memory + src, length);
}

void WasmMemory::memset(uint32_t dst, uint8_t value, uint32_t length) {
    if (dst + length > current * PAGE_SIZE) {
        trap("out of bounds memory access");
    }
    std::memset(memory + dst, value, length);
}

WasmTable::WasmTable(valtype type, uint32_t initial, uint32_t maximum)
    : elements(static_cast<WasmValue *>(calloc(initial, sizeof(WasmValue)))),
      current(initial), maximum(maximum), type(type) {}

WasmTable::WasmTable(WasmTable &&table) {
    type = table.type;
    current = table.current;
    maximum = table.maximum;
    elements = table.elements;
    table.elements = nullptr;
}

WasmTable::~WasmTable() { free(elements); }

uint32_t WasmTable::grow(uint32_t delta, WasmValue value) {
    uint32_t new_current = current + delta;
    if (new_current <= maximum) {
        return -1;
    }

    WasmValue *new_elements = static_cast<WasmValue *>(
        realloc(elements, new_current * sizeof(WasmValue)));
    if (new_elements == NULL)
        return -1;
    elements = new_elements;
    std::fill(elements + current, elements + new_current, value);

    uint32_t old_current = current;
    current = new_current;
    return old_current;
}

WasmValue WasmTable::get(uint32_t idx) {
    if (idx >= current) {
        trap("undefined element");
    }
    return elements[idx];
}

void WasmTable::set(uint32_t idx, WasmValue value) {
    if (idx >= current) {
        trap("out of bounds table access");
    }
    elements[idx] = value;
}

void WasmTable::copy_into(uint32_t dst, const WasmValue *data,
                          uint32_t length) {
    if (dst + length > current) {
        trap("out of bounds table access");
    }
    std::memcpy(elements + dst, data, length * sizeof(WasmValue));
}

void WasmTable::memcpy(uint32_t dst, uint32_t src, uint32_t length) {
    if (dst + length > current || src + length > current) {
        trap("out of bounds table access");
    }
    std::memcpy(elements + dst, elements + src, length * sizeof(WasmValue));
}

void WasmTable::memset(uint32_t dst, WasmValue value, uint32_t length) {
    if (dst + length > current) {
        trap("out of bounds table access");
    }
    std::fill(elements + dst, elements + dst + length, value);
}
} // namespace mitey

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
