#include "instance.hpp"
#include "module.hpp"
#include "spec.hpp"
#include <algorithm>
#include <cassert>
#include <cmath>
#include <functional>
#include <limits>

#ifdef WASM_DEBUG
#include <iostream>
#endif

namespace mitey {

Instance::Instance(std::shared_ptr<Module> module)
    : module(module), memory(nullptr), initial_stack(nullptr, 0),
      initial_control_stack(nullptr, 0), if_jumps(module->if_jumps),
      block_ends(module->block_ends) {

    uint32_t buffer_size = 0;
    std::function<void(uint8_t *)> cb = [](uint8_t *) {};
    auto alloc =
        [&]<template <typename T, size_t...> class Container, typename T>(
            Container<T> *member, uint32_t size) {
            uint32_t offset = buffer_size;
            buffer_size += sizeof(T) * size;
            buffer_size += -buffer_size & 15;

            auto prev_cb = cb;
            cb = [=](uint8_t *raw_buffer) {
                new (member) Container<T>((T *)(raw_buffer + offset), size);
                prev_cb(raw_buffer);
            };
        };

    alloc(&initial_stack, STACK_SIZE / sizeof(WasmValue));
    alloc(&initial_control_stack, MAX_DEPTH);
    alloc(&functions, module->functions.size());
    alloc(&types, module->types.size());
    alloc(&globals, module->globals.size());
    alloc(&elements, module->elements.size());
    alloc(&data_segments, module->data_segments.size());
    alloc(&tables, module->tables.size());

    // align to 2mb (in hopes of getting a huge page)
    constexpr auto TWO_MB = 1ULL << 21;
    buffer_size += -buffer_size & (TWO_MB - 1);

    buffer = std::make_unique<uint8_t[]>(buffer_size);
    cb(buffer.get());
}

void Instance::initialize(const Imports &imports) {
    auto get_import = [&](const ImportSpecifier &specifier) -> ExportValue {
        auto [module_name, field_name] = specifier;
        if (!imports.contains(module_name)) {
            error<link_error>("unknown import");
        }
        auto &import_module = imports.at(module_name);
        if (!import_module.contains(field_name)) {
            error<link_error>("unknown import");
        }
        auto &import = import_module.at(field_name);
        if (static_cast<mitey::ImExDesc>(import.index()) !=
            module->imports.at(module_name).at(field_name)) {
            error<link_error>("incompatible import type");
        }
        return import;
    };

    if (module->memory.exists) {
        if (module->memory.import) {
            auto imported_memory = std::get<std::shared_ptr<WasmMemory>>(
                get_import(*module->memory.import));

            if (imported_memory->size() < module->memory.min ||
                imported_memory->max() > module->memory.max) {
                error<link_error>("incompatible import type");
            }

            memory = imported_memory;
        } else {
            memory = std::make_shared<WasmMemory>(module->memory.min,
                                                  module->memory.max);
        }
    }

    for (uint32_t i = 0; i < functions.size(); i++) {
        const auto &fn = module->functions[i];
        if (fn.import) {
            auto imported_function =
                std::get<FunctionInfo>(get_import(*fn.import));

            if (imported_function.type !=
                RuntimeType::from_signature(fn.type)) {
                error<link_error>("incompatible import type");
            }

            functions[i] = imported_function;
        } else {
            functions[i] =
                FunctionInfo(fn.type, self.lock(), fn.start, fn.locals);
        }
    }

    for (uint32_t i = 0; i < types.size(); i++) {
        types[i] = RuntimeType::from_signature(module->types[i]);
    }

    for (uint32_t i = 0; i < globals.size(); i++) {
        const auto &global = module->globals[i];
        if (global.import) {
            auto imported_global = std::get<std::shared_ptr<WasmGlobal>>(
                get_import(*global.import));

            if (imported_global->type != global.type ||
                imported_global->_mut != global.mutability) {
                error<link_error>("incompatible import type");
            }

            globals[i] = imported_global;
        } else {
            globals[i] = std::make_shared<WasmGlobal>(
                global.type, global.mutability,
                interpret_const_inplace(global.initializer));
        }
    }

    for (uint32_t i = 0; i < tables.size(); i++) {
        const auto &table = module->tables[i];
        if (table.import) {
            auto imported_table =
                std::get<std::shared_ptr<WasmTable>>(get_import(*table.import));

            if (imported_table->size() < table.min ||
                imported_table->max() > table.max ||
                imported_table->type != table.type) {
                error<link_error>("incompatible import type");
            }

            tables[i] = imported_table;
        } else {
            tables[i] =
                std::make_shared<WasmTable>(table.type, table.min, table.max);
        }
    }

    uint8_t *iter = module->element_start;
    for (uint32_t i = 0; i < elements.size(); i++) {
        uint32_t flags = read_leb128(iter);

        if (flags & 1) {
            if (flags & 0b10) {
                if (flags & 0b100) {
                    // flags = 7
                    // characteristics: declarative, elem type + exprs
                    valtype reftype = static_cast<valtype>(*iter++);
                    uint32_t n_elements = read_leb128(iter);
                    for (uint32_t j = 0; j < n_elements; j++) {
                        interpret_const(iter);
                    }
                    elements[i] = ElementSegment{reftype, {}};
                } else {
                    // flags = 3
                    // characteristics: declarative, elem kind + indices
                    /* uint8_t elemkind = * */ iter++;
                    uint32_t n_elements = read_leb128(iter);
                    for (uint32_t j = 0; j < n_elements; j++) {
                        read_leb128(iter);
                    }
                    elements[i] = ElementSegment{valtype::funcref, {}};
                }
            } else {
                if (flags & 0b100) {
                    // flags = 5
                    // characteristics: passive, elem type + exprs
                    valtype reftype = static_cast<valtype>(*iter++);
                    uint32_t n_elements = read_leb128(iter);
                    std::vector<WasmValue> elem(n_elements);
                    for (uint32_t j = 0; j < n_elements; j++) {
                        elem[j] = interpret_const(iter);
                    }
                    elements[i] = ElementSegment{reftype, elem};
                } else {
                    // flags = 1
                    // characteristics: passive, elem kind + indices
                    /* uint8_t elemkind = * */ iter++;
                    uint32_t n_elements = read_leb128(iter);
                    std::vector<WasmValue> elem(n_elements);
                    for (uint32_t j = 0; j < n_elements; j++) {
                        elem[j] = &functions[read_leb128(iter)];
                    }
                    elements[i] = ElementSegment{valtype::funcref, elem};
                }
            }
        } else {
            valtype reftype;

            auto table = tables[flags & 0b10 ? read_leb128(iter) : 0];
            uint32_t offset = interpret_const(iter).u32;
            uint16_t reftype_or_elemkind = flags & 0b10 ? *iter++ : 256;
            uint32_t n_elements = read_leb128(iter);
            if (offset + n_elements > table->size()) {
                error<uninstantiable_error>("out of bounds table access");
            }

            std::vector<WasmValue> elem(n_elements);
            if (flags & 0b100) {
                // flags = 4 or 6
                // characteristics: active, elem type + exprs
                if (reftype_or_elemkind == 256)
                    reftype_or_elemkind =
                        static_cast<uint16_t>(valtype::funcref);
                reftype = static_cast<valtype>(reftype_or_elemkind);

                for (uint32_t j = 0; j < n_elements; j++) {
                    WasmValue ref = interpret_const(iter);
                    elem[j] = ref;
                    if (offset + j >= table->size()) {
                        error<uninstantiable_error>(
                            "out of bounds table access");
                    }
                    table->set(offset + j, ref);
                }
            } else {
                if (reftype_or_elemkind == 256)
                    reftype_or_elemkind = 0;
                reftype = valtype::funcref;

                // flags = 0 or 2
                // characteristics: active, elem kind + indices
                for (uint32_t j = 0; j < n_elements; j++) {
                    uint32_t elem_idx = read_leb128(iter);
                    WasmValue funcref = &functions[elem_idx];
                    elem[j] = funcref;
                    if (offset + j >= table->size()) {
                        error<uninstantiable_error>(
                            "out of bounds table access");
                    }
                    table->set(offset + j, funcref);
                }
            }
            elements[i] = ElementSegment{reftype, {}};
        }
    }

    for (uint32_t i = 0; i < data_segments.size(); i++) {
        const auto &data = module->data_segments[i];
        if (data.initializer) {
            uint32_t offset = interpret_const_inplace(data.initializer).u32;
            try {
                memory->copy_into(offset, 0, data, data.data.size());
            } catch (const trap_error &e) {
                error<uninstantiable_error>(e.what());
            }

            data_segments[i] = {};
        } else {
            data_segments[i] = data;
        }
    }

    for (const auto &[name, export_] : module->exports) {
        switch (export_.desc) {
        case ImExDesc::func:
            exports[name] = externalize_function(functions[export_.idx]);
            break;
        case ImExDesc::table:
            exports[name] = tables[export_.idx];
            break;
        case ImExDesc::mem:
            exports[name] = memory;
            break;
        case ImExDesc::global:
            exports[name] = globals[export_.idx];
            break;
        }
    }

    if (module->start != std::numeric_limits<uint32_t>::max()) {
        const auto &fn = functions[module->start];
        if (fn.type.n_params || fn.type.n_results) {
            error<validation_error>("start function");
        }
        try {
            entrypoint(fn, initial_stack, initial_control_stack);
        } catch (const trap_error &e) {
            error<uninstantiable_error>(e.what());
        }
    }
}

WasmValue Instance::interpret_const(uint8_t *&iter) {
    std::vector<WasmValue> stack;

#define OP(ty, op)                                                             \
    {                                                                          \
        auto arg1 = stack.back();                                              \
        stack.pop_back();                                                      \
        auto arg2 = stack.back();                                              \
        stack.pop_back();                                                      \
        stack.push_back(arg1.ty op arg2.ty);                                   \
        break;                                                                 \
    }
#define I32_OP(op) OP(i32, op)
#define I64_OP(op) OP(i64, op)

    while (1) {
        uint8_t byte = *iter++;
#ifdef WASM_DEBUG
        std::cerr << "reading instruction " << instructions[byte].c_str()
                  << " at " << iter - module->bytes.get() << std::endl;
#endif

        using enum Instruction;
        if (static_cast<Instruction>(byte) == end) {
            break;
        }
        switch (static_cast<Instruction>(byte)) {
        case i32const:
            stack.push_back((int32_t)read_sleb128(iter));
            break;
        case i64const:
            stack.push_back((int64_t)read_sleb128(iter));
            break;
        case f32const: {
            float x;
            std::memcpy(&x, iter, sizeof(float));
            stack.push_back(x);
            iter += sizeof(float);
            break;
        }
        case f64const: {
            double x;
            std::memcpy(&x, iter, sizeof(double));
            stack.push_back(x);
            iter += sizeof(double);
            break;
        }
        case globalget:
            stack.push_back(globals[read_leb128(iter)]->value);
            break;
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
            read_leb128(iter);
            stack.push_back((void *)nullptr);
            break;
        }
        case ref_func: {
            uint32_t func_idx = safe_read_leb128<uint32_t>(iter);
            stack.push_back(&functions[func_idx]);
            break;
        }
        default:
            __builtin_unreachable();
        }
    }

    return stack.back();

#undef OP
#undef I32_OP
#undef I64_OP
} // namespace mitey

FunctionInfo Instance::externalize_function(const FunctionInfo &fn) {
    if (fn.static_fn || fn.dyn_fn) {
        // already external
        return fn;
    } else {
        return FunctionInfo(fn.type, [&](WasmValue *extern_stack) {
            const auto &type = fn.type;

            for (uint32_t i = 0; i < type.n_params; i++) {
                initial_stack.push(extern_stack[i]);
            }

            try {
                entrypoint(fn, initial_stack, initial_control_stack);
            } catch (const trap_error &e) {
                initial_stack.clear();
                initial_control_stack.clear();
                throw;
            }

            initial_stack -= type.n_results;
            for (uint32_t i = 0; i < type.n_results; i++) {
                extern_stack[i] = initial_stack[i];
            }
        });
    }
}

void Instance::entrypoint(const FunctionInfo &fn, tape<WasmValue> &stack,
                          tape<BrTarget> &control_stack) {
    auto prev_start = control_stack.get_start();
    control_stack.set_start(control_stack.unsafe_ptr());

    try {
        call_function_info(fn, nullptr, stack, control_stack);
        control_stack.set_start(prev_start);
    } catch (const trap_error &) {
        control_stack.set_start(prev_start);
        throw;
    }
}

inline void Instance::call_function_info(const FunctionInfo &fn,
                                         uint8_t *return_to,
                                         tape<WasmValue> &stack,
                                         tape<BrTarget> &control_stack) {
    if (fn.wasm_fn) {
        // parameters are the first locals and they're taken from the top of
        // the stack
        stack -= fn.type.n_params;
        WasmValue *locals_start = stack.unsafe_ptr();
        stack += fn.type.n_params + fn.wasm_fn.n_locals;
        WasmValue *locals_end = stack.unsafe_ptr();

        WasmValue *nonparam_locals = locals_start + fn.type.n_params;
        std::memset((void *)nonparam_locals, 0,
                    (locals_end - nonparam_locals) * sizeof(WasmValue));

        StackFrame prev = frame;
        auto cf_start = control_stack.get_start();

        frame = {locals_start, control_stack.get_start()};
        control_stack.set_start(control_stack.unsafe_ptr());
        control_stack.push({locals_start, return_to,
                            static_cast<uint32_t>(fn.type.n_results)});

        interpret(fn.wasm_fn.start, stack, control_stack);

        control_stack.set_start(cf_start);
        frame = prev;
    } else {
        stack -= fn.type.n_params;
        if (fn.static_fn != nullptr) {
            fn.static_fn(stack.unsafe_ptr());
        } else {
            fn.dyn_fn(stack.unsafe_ptr());
        }
        stack += fn.type.n_results;
    }
}

using Handler = void(Instance &, uint8_t *, tape<WasmValue> &,
                     tape<BrTarget> &);
#define HANDLER(name)                                                          \
    void name(Instance &instance, uint8_t *iter, tape<WasmValue> &stack,       \
              tape<BrTarget> &control_stack)

using i32 = int32_t;
using u32 = uint32_t;
using i64 = int64_t;
using u64 = uint64_t;
using f32 = float;
using f64 = double;

static void __attribute__((noinline, preserve_most))
slow_memmove(WasmValue *dst, const WasmValue *src, size_t n) {
    std::memmove(dst, src, n * sizeof(WasmValue));
}

/*
    (functions and ifs are blocks)

    enter into loop          -> valid if stack <= param_type
    enter into block         -> valid if stack <= param_type
    br depth is loop (enter) -> valid if stack <= param_type
    br depth is block (exit) -> valid if stack <= return_type
    exit from loop           -> valid if stack == return_type
    exit from block          -> valid if stack == return_type
*/
static inline bool brk(Instance &, uint8_t *&iter, tape<WasmValue> &stack,
                       tape<BrTarget> &control_stack, uint32_t depth) {
    control_stack -= depth;
    BrTarget target = control_stack.pop();
    stack -= target.arity;
    std::memmove(target.stack, stack.unsafe_ptr(), sizeof(WasmValue));
    if (target.arity > 1) [[unlikely]] {
        slow_memmove(target.stack, stack.unsafe_ptr(), target.arity);
    }
    stack = target.stack + target.arity;
    iter = target.dest;
    return control_stack.empty();
};
#define BRK(depth) brk(instance, iter, stack, control_stack, depth)

#define UNARY_OP(type, op)                                                     \
    stack[-1] = op(stack[-1].type);                                            \
    nextop()
#define TRUNC(type, op, lower, upper)                                          \
    {                                                                          \
        if (!std::isfinite(stack[-1].type)) {                                  \
            if (std::isnan(stack[-1].type)) {                                  \
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
    nextop()
#define BINARY_OP(type, op)                                                    \
    {                                                                          \
        stack--;                                                               \
        stack[-1] = stack[-1].type op stack[0].type;                           \
        nextop();                                                              \
    }
#define BINARY_FN(type, fn)                                                    \
    {                                                                          \
        stack--;                                                               \
        stack[-1] = fn(stack[-1].type, stack[0].type);                         \
        nextop();                                                              \
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
        nextop();                                                              \
    }
#define IREM(type)                                                             \
    {                                                                          \
        stack--;                                                               \
        if (stack[0].type == 0) {                                              \
            trap("integer divide by zero");                                    \
        }                                                                      \
        if (std::is_signed_v<type> &&                                          \
            stack[0].type == static_cast<type>(-1) &&                          \
            stack[-1].type == std::numeric_limits<type>::min()) [[unlikely]] { \
            stack[-1] = static_cast<type>(0);                                  \
        } else {                                                               \
            stack[-1] = stack[-1].type % stack[0].type;                        \
        }                                                                      \
        nextop();                                                              \
    }
#define MINMAX(type, fn)                                                       \
    {                                                                          \
        stack--;                                                               \
        if (std::isnan(stack[-1].type) || std::isnan(stack[0].type)) {         \
            stack[-1].type = std::numeric_limits<type>::quiet_NaN();           \
        } else {                                                               \
            stack[-1].type = fn(stack[-1].type, stack[0].type);                \
        }                                                                      \
        nextop();                                                              \
    }
#define SHIFT(type, op)                                                        \
    {                                                                          \
        stack--;                                                               \
        stack[-1] = stack[-1].type op(stack[0].type % (sizeof(type) * 8));     \
        nextop();                                                              \
    }
#define TRUNC_SAT(from, to)                                                    \
    {                                                                          \
        if (stack[-1].from < std::numeric_limits<to>::min()) {                 \
            stack[-1].to = std::numeric_limits<to>::min();                     \
        } else if (stack[-1].from > std::numeric_limits<to>::max()) {          \
            stack[-1].to = std::numeric_limits<to>::max();                     \
        } else {                                                               \
            stack[-1].to = static_cast<to>(stack[-1].from);                    \
        }                                                                      \
        nextop();                                                              \
    }

#define LOAD(type, memtype)                                                    \
    {                                                                          \
        uint32_t align = 1 << *iter++;                                         \
        uint32_t offset = read_leb128(iter);                                   \
        stack[-1].type =                                                       \
            instance.memory->load<memtype>(stack[-1].u32, offset, align);      \
        nextop();                                                              \
    }

#define STORE(type, stacktype)                                                 \
    {                                                                          \
        stack -= 2;                                                            \
        uint32_t align = 1 << *iter++;                                         \
        uint32_t offset = read_leb128(iter);                                   \
        instance.memory->store<type>(stack[0].u32, offset, align,              \
                                     static_cast<type>(stack[1].stacktype));   \
        nextop();                                                              \
    }
#ifdef WASM_DEBUG
#define nextop()                                                               \
    do {                                                                       \
        uint8_t byte = *iter++;                                                \
        std::cerr << "reading instruction " << instructions[byte].c_str()      \
                  << std::endl;                                                \
        std::cerr << "stack contents: ";                                       \
        for (WasmValue *p = instance.frame.locals; p < stack.unsafe_ptr();     \
             p++) {                                                            \
            std::cerr << p->u64 << " ";                                        \
        }                                                                      \
        std::cerr << std::endl << std::endl;                                   \
        [[clang::musttail]] return handlers[byte](instance, iter, stack,       \
                                                  control_stack);              \
    } while (0)
#else
#define nextop()                                                               \
    do {                                                                       \
        uint8_t byte = *iter++;                                                \
        [[clang::musttail]] return handlers[byte](instance, iter, stack,       \
                                                  control_stack);              \
    } while (0)
#endif

#define DECL_HANDLER(name, str, byte) HANDLER(name);
FOREACH_INSTRUCTION(DECL_HANDLER)
FOREACH_MULTIBYTE_INSTRUCTION(DECL_HANDLER)
#undef DECL_HANDLER

consteval std::array<Handler *, 256> make_handlers() {
    std::array<Handler *, 256> handlers = {};

#define DEFINE_LABEL(name, _, byte) handlers[byte] = &name;
    FOREACH_INSTRUCTION(DEFINE_LABEL)
#undef DEFINE_LABEL

    return handlers;
}

consteval std::array<Handler *, 256> make_fc_handlers() {
    std::array<Handler *, 256> handlers = {};

#define DEFINE_LABEL(name, _, byte) handlers[byte] = &name;
    FOREACH_MULTIBYTE_INSTRUCTION(DEFINE_LABEL)
#undef DEFINE_LABEL

    return handlers;
}

static auto handlers = make_handlers();
static auto fc_handlers = make_fc_handlers();

void Instance::interpret(uint8_t *iter, tape<WasmValue> &stack,
                         tape<BrTarget> &control_stack) {
    uint8_t byte = *iter++;
    return handlers[byte](*this, iter, stack, control_stack);
}

HANDLER(unreachable) {
    trap("unreachable");
    nextop();
}

HANDLER(nop) { nextop(); }
HANDLER(block) {
    auto sn = RuntimeType::read_blocktype(instance.types, iter);
    if (instance.block_ends.empty())
        __builtin_unreachable();
    const auto &block_end = instance.block_ends.find(iter)->second;
    control_stack.push({stack.unsafe_ptr() - sn.n_params, block_end,
                        static_cast<uint32_t>(sn.n_results)});
    nextop();
}
HANDLER(loop) {
    // reading blocktype each time maybe not efficient?
    uint8_t *loop_start = iter - 1;
    auto sn = RuntimeType::read_blocktype(instance.types, iter);
    control_stack.push(
        // iter - 1 so br goes back to the loop
        {stack.unsafe_ptr() - sn.n_params, loop_start,
         static_cast<uint32_t>(sn.n_params)});
    nextop();
}
HANDLER(if_) {
    auto sn = RuntimeType::read_blocktype(instance.types, iter);
    uint32_t cond = stack.pop().u32;
    if (instance.if_jumps.empty())
        __builtin_unreachable();
    const auto &if_jump = instance.if_jumps.find(iter)->second;
    control_stack.push({stack.unsafe_ptr() - sn.n_params, if_jump.end,
                        static_cast<uint32_t>(sn.n_results)});
    if (!cond)
        iter = if_jump.else_;
    nextop();
}
HANDLER(else_) {
    // if the else block is reached, the if block is done
    // might be faster to have another dictionary for else block ->
    // end so this can just be iter = end_block todo: look at what
    // compiler optimizes to
    BRK(0);
    nextop();
}
HANDLER(end) {
    if (control_stack.size() == 1) {
        // function end block
        BRK(0);
        return;
    } else {
        // we don't know if this is a block or loop
        // so can't do brk(0)
        // BUT validation has confirmed that the result is
        // the only thing left on the stack, so we can just
        // pop the control stack (since the result is already in
        // place)
        control_stack.pop();
    }
    nextop();
}
HANDLER(br) {
    if (BRK(read_leb128(iter)))
        return;
    nextop();
}
HANDLER(br_if) {
    uint32_t depth = read_leb128(iter);
    if (stack.pop().u32)
        if (BRK(depth))
            return;
    nextop();
}
HANDLER(br_table) {
    uint32_t v = stack.pop().u32;
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
    if (BRK(depth))
        return;
    nextop();
}
HANDLER(return_) {
    if (BRK(control_stack.size() - 1))
        return;
    nextop();
}
HANDLER(call) {
    FunctionInfo &fn = instance.functions[read_leb128(iter)];
    instance.call_function_info(fn, iter, stack, control_stack);
    nextop();
}
HANDLER(call_indirect) {
    uint32_t type_idx = read_leb128(iter);
    uint32_t table_idx = read_leb128(iter);
    uint32_t elem_idx = stack.pop().u32;

    if (elem_idx >= instance.tables[table_idx]->size()) {
        trap("undefined element");
    }
    Funcref funcref = instance.tables[table_idx]->get(elem_idx);
    if (!funcref) {
        trap("uninitialized element");
    }
    if (funcref->type != instance.types[type_idx]) {
        trap("indirect call type mismatch");
    }

    // this is so bad, there's so much repetition
    // entrypooint and call_function_info need to be revamped
    auto &fn = *funcref;
    if (fn.wasm_fn) {
        fn.wasm_fn.instance->entrypoint(fn, stack, control_stack);
    } else {
        stack -= fn.type.n_params;
        if (fn.static_fn != nullptr) {
            fn.static_fn(stack.unsafe_ptr());
        } else {
            fn.dyn_fn(stack.unsafe_ptr());
        }
        stack += fn.type.n_results;
    }
    nextop();
}
HANDLER(drop) {
    stack.pop();
    nextop();
}
HANDLER(select) {
    stack -= 2;
    stack[-1] = stack[-!!stack[1].u32];
    nextop();
}
HANDLER(select_t) {
    /* uint32_t n_results = */ read_leb128(iter);
    // skip result types
    iter++;
    stack -= 2;
    stack[-1] = stack[-!!stack[1].u32];
    nextop();
}
HANDLER(localget) {
    stack.push(instance.frame.locals[read_leb128(iter)]);
    nextop();
}
HANDLER(localset) {
    instance.frame.locals[read_leb128(iter)] = stack.pop();
    nextop();
}
HANDLER(localtee) {
    instance.frame.locals[read_leb128(iter)] = stack[-1];
    nextop();
}
HANDLER(tableget) {
    stack.push(instance.tables[read_leb128(iter)]->get(stack.pop().u32));
    nextop();
}
HANDLER(tableset) {
    stack -= 2;
    instance.tables[read_leb128(iter)]->set(stack[0].u32, stack[1]);
    nextop();
}
HANDLER(globalget) {
    stack.push(instance.globals[read_leb128(iter)]->value);
    nextop();
}
HANDLER(globalset) {
    instance.globals[read_leb128(iter)]->value = stack.pop();
    nextop();
}
HANDLER(memorysize) {
    /* uint32_t mem_idx = */ read_leb128(iter);
    stack.push(instance.memory->size());
    nextop();
}
HANDLER(memorygrow) {
    /* uint32_t mem_idx = */ read_leb128(iter);
    stack[-1].u32 = instance.memory->grow(stack[-1].u32);
    nextop();
}
HANDLER(i32const) {
    stack.push((int32_t)read_sleb128(iter));
    nextop();
}
HANDLER(i64const) {
    stack.push((int64_t)read_sleb128(iter));
    nextop();
}
HANDLER(f32const) {
    float x;
    std::memcpy(&x, iter, sizeof(float));
    stack.push(x);
    iter += sizeof(float);
    nextop();
}
HANDLER(f64const) {
    double x;
    std::memcpy(&x, iter, sizeof(double));
    stack.push(x);
    iter += sizeof(double);
    nextop();
}
// clang-format off
HANDLER(i32load)      { LOAD(u32, uint32_t); }
HANDLER(i64load)      { LOAD(u64, uint64_t); }
HANDLER(f32load)      { LOAD(f32, float); }
HANDLER(f64load)      { LOAD(f64, double); }
HANDLER(i32load8_s)   { LOAD(i32, int8_t); }
HANDLER(i32load8_u)   { LOAD(u32, uint8_t); }
HANDLER(i32load16_s)  { LOAD(i32, int16_t); }
HANDLER(i32load16_u)  { LOAD(u32, uint16_t); }
HANDLER(i64load8_s)   { LOAD(i64, int8_t); }
HANDLER(i64load8_u)   { LOAD(u64, uint8_t); }
HANDLER(i64load16_s)  { LOAD(i64, int16_t); }
HANDLER(i64load16_u)  { LOAD(u64, uint16_t); }
HANDLER(i64load32_s)  { LOAD(i64, int32_t); }
HANDLER(i64load32_u)  { LOAD(u64, uint32_t); }
HANDLER(i32store)     { STORE(uint32_t, u32); }
HANDLER(i64store)     { STORE(uint64_t, u64); }
HANDLER(f32store)     { STORE(float, f32); }
HANDLER(f64store)     { STORE(double, f64); }
HANDLER(i32store8)    { STORE(uint8_t, u32); }
HANDLER(i32store16)   { STORE(uint16_t, u32); }
HANDLER(i64store8)    { STORE(uint8_t, u64); }
HANDLER(i64store16)   { STORE(uint16_t, u64); }
HANDLER(i64store32)   { STORE(uint32_t, u64); }
HANDLER(i32eqz)       { UNARY_OP (i32, 0 ==); }
HANDLER(i64eqz)       { UNARY_OP (i64, 0 ==); }
HANDLER(i32eq)        { BINARY_OP(i32, ==); }
HANDLER(i64eq)        { BINARY_OP(i64, ==); }
HANDLER(i32ne)        { BINARY_OP(i32, !=); }
HANDLER(i64ne)        { BINARY_OP(i64, !=); }
HANDLER(i32lt_s)      { BINARY_OP(i32, < ); }
HANDLER(i64lt_s)      { BINARY_OP(i64, < ); }
HANDLER(i32lt_u)      { BINARY_OP(u32, < ); }
HANDLER(i64lt_u)      { BINARY_OP(u64, < ); }
HANDLER(i32gt_s)      { BINARY_OP(i32, > ); }
HANDLER(i64gt_s)      { BINARY_OP(i64, > ); }
HANDLER(i32gt_u)      { BINARY_OP(u32, > ); }
HANDLER(i64gt_u)      { BINARY_OP(u64, > ); }
HANDLER(i32le_s)      { BINARY_OP(i32, <=); }
HANDLER(i64le_s)      { BINARY_OP(i64, <=); }
HANDLER(i32le_u)      { BINARY_OP(u32, <=); }
HANDLER(i64le_u)      { BINARY_OP(u64, <=); }
HANDLER(i32ge_s)      { BINARY_OP(i32, >=); }
HANDLER(i64ge_s)      { BINARY_OP(i64, >=); }
HANDLER(i32ge_u)      { BINARY_OP(u32, >=); }
HANDLER(i64ge_u)      { BINARY_OP(u64, >=); }
HANDLER(f32eq)        { BINARY_OP(f32, ==); }
HANDLER(f64eq)        { BINARY_OP(f64, ==); }
HANDLER(f32ne)        { BINARY_OP(f32, !=); }
HANDLER(f64ne)        { BINARY_OP(f64, !=); }
HANDLER(f32lt)        { BINARY_OP(f32, < ); }
HANDLER(f64lt)        { BINARY_OP(f64, < ); }
HANDLER(f32gt)        { BINARY_OP(f32, > ); }
HANDLER(f64gt)        { BINARY_OP(f64, > ); }
HANDLER(f32le)        { BINARY_OP(f32, <=); }
HANDLER(f64le)        { BINARY_OP(f64, <=); }
HANDLER(f32ge)        { BINARY_OP(f32, >=); }
HANDLER(f64ge)        { BINARY_OP(f64, >=); }
HANDLER(i32clz)       { UNARY_FN (u32, std::countl_zero); }
HANDLER(i64clz)       { UNARY_FN (u64, (uint64_t)std::countl_zero); }
HANDLER(i32ctz)       { UNARY_FN (u32, std::countr_zero); }
HANDLER(i64ctz)       { UNARY_FN (u64, (uint64_t)std::countr_zero); }
HANDLER(i32popcnt)    { UNARY_FN (u32, std::popcount); }
HANDLER(i64popcnt)    { UNARY_FN (u64, (uint64_t)std::popcount); }
HANDLER(i32add)       { BINARY_OP(u32, + ); }
HANDLER(i64add)       { BINARY_OP(u64, + ); }
HANDLER(i32sub)       { BINARY_OP(u32, - ); }
HANDLER(i64sub)       { BINARY_OP(u64, - ); }
HANDLER(i32mul)       { BINARY_OP(u32, * ); }
HANDLER(i64mul)       { BINARY_OP(u64, * ); }
HANDLER(i32div_s)     { IDIV     (i32); }
HANDLER(i64div_s)     { IDIV     (i64); }
HANDLER(i32div_u)     { IDIV     (u32); }
HANDLER(i64div_u)     { IDIV     (u64); }
HANDLER(i32rem_s)     { IREM     (i32); }
HANDLER(i64rem_s)     { IREM     (i64); }
HANDLER(i32rem_u)     { IREM     (u32); }
HANDLER(i64rem_u)     { IREM     (u64); }
HANDLER(i32and)       { BINARY_OP(u32, & ); }
HANDLER(i64and)       { BINARY_OP(u64, & ); }
HANDLER(i32or)        { BINARY_OP(u32, | ); }
HANDLER(i64or)        { BINARY_OP(u64, | ); }
HANDLER(i32xor)       { BINARY_OP(u32, ^ ); }
HANDLER(i64xor)       { BINARY_OP(u64, ^ ); }
HANDLER(i32shl)       { SHIFT    (u32, <<); }
HANDLER(i64shl)       { SHIFT    (u64, <<); }
HANDLER(i32shr_s)     { SHIFT    (i32, >>); }
HANDLER(i64shr_s)     { SHIFT    (i64, >>); }
HANDLER(i32shr_u)     { SHIFT    (u32, >>); }
HANDLER(i64shr_u)     { SHIFT    (u64, >>); }
HANDLER(i32rotl)      { BINARY_FN(u32, std::rotl); }
HANDLER(i64rotl)      { BINARY_FN(u64, std::rotl); }
HANDLER(i32rotr)      { BINARY_FN(u32, std::rotr); }
HANDLER(i64rotr)      { BINARY_FN(u64, std::rotr); }
HANDLER(f32abs)       { UNARY_FN (f32, std::abs); }
HANDLER(f64abs)       { UNARY_FN (f64, std::abs); }
HANDLER(f32neg)       { UNARY_OP (f32, -); }
HANDLER(f64neg)       { UNARY_OP (f64, -); }
HANDLER(f32ceil)      { UNARY_FN (f32, std::ceil); }
HANDLER(f64ceil)      { UNARY_FN (f64, std::ceil); }
HANDLER(f32floor)     { UNARY_FN (f32, std::floor); }
HANDLER(f64floor)     { UNARY_FN (f64, std::floor); }
HANDLER(f32trunc)     { UNARY_FN (f32, std::trunc); }
HANDLER(f64trunc)     { UNARY_FN (f64, std::trunc); }
HANDLER(f32nearest)   { UNARY_FN (f32, std::nearbyint); }
HANDLER(f64nearest)   { UNARY_FN (f64, std::nearbyint); }
HANDLER(f32sqrt)      { UNARY_FN (f32, std::sqrt); }
HANDLER(f64sqrt)      { UNARY_FN (f64, std::sqrt); }
HANDLER(f32add)       { BINARY_OP(f32, +); }
HANDLER(f64add)       { BINARY_OP(f64, +); }
HANDLER(f32sub)       { BINARY_OP(f32, -); }
HANDLER(f64sub)       { BINARY_OP(f64, -); }
HANDLER(f32mul)       { BINARY_OP(f32, *); }
HANDLER(f64mul)       { BINARY_OP(f64, *); }
HANDLER(f32div)       { BINARY_OP(f32, /); }
HANDLER(f64div)       { BINARY_OP(f64, /); }
HANDLER(f32min)       { MINMAX   (f32, std::min); }
HANDLER(f64min)       { MINMAX   (f64, std::min); }
HANDLER(f32max)       { MINMAX   (f32, std::max); }
HANDLER(f64max)       { MINMAX   (f64, std::max); }
HANDLER(f32copysign)  { BINARY_FN(f32, std::copysign); }
HANDLER(f64copysign)  { BINARY_FN(f64, std::copysign); }
HANDLER(i32wrap_i64)      { UNARY_OP(i64, (int32_t)); }
HANDLER(i64extend_i32_s)  { UNARY_OP(i32, (int64_t)); }
HANDLER(i64extend_i32_u)  { UNARY_OP(u32, (uint64_t)); }
HANDLER(i32trunc_f32_s)   { TRUNC   (f32, (int32_t),           -2147483777.,           2147483648.); }
HANDLER(i64trunc_f32_s)   { TRUNC   (f32, (int64_t),  -9223373136366404000.,  9223372036854776000.); }
HANDLER(i32trunc_f32_u)   { TRUNC   (f32, (uint32_t),                   -1.,           4294967296.); }
HANDLER(i64trunc_f32_u)   { TRUNC   (f32, (uint64_t),                   -1., 18446744073709552000.); }
HANDLER(i32trunc_f64_s)   { TRUNC   (f64, (int32_t),           -2147483649.,           2147483648.); }
HANDLER(i64trunc_f64_s)   { TRUNC   (f64, (int64_t),  -9223372036854777856.,  9223372036854776000.); }
HANDLER(i32trunc_f64_u)   { TRUNC   (f64, (uint32_t),                   -1.,           4294967296.); }
HANDLER(i64trunc_f64_u)   { TRUNC   (f64, (uint64_t),                   -1., 18446744073709552000.); }
HANDLER(f32convert_i32_s) { UNARY_OP(i32, (float)); }
HANDLER(f64convert_i32_s) { UNARY_OP(i32, (double)); }
HANDLER(f32convert_i32_u) { UNARY_OP(u32, (float)); }
HANDLER(f64convert_i32_u) { UNARY_OP(u32, (double)); }
HANDLER(f32convert_i64_s) { UNARY_OP(i64, (float)); }
HANDLER(f64convert_i64_s) { UNARY_OP(i64, (double)); }
HANDLER(f32convert_i64_u) { UNARY_OP(u64, (float)); }
HANDLER(f64convert_i64_u) { UNARY_OP(u64, (double)); }
HANDLER(f32demote_f64)    { UNARY_OP(f64, (float)); }
HANDLER(f64promote_f32)   { UNARY_OP(f32, (double)); }
// without type assertions these are noops
HANDLER(i32reinterpret_f32) { nextop(); }
HANDLER(f32reinterpret_i32) { nextop(); }
HANDLER(i64reinterpret_f64) { nextop(); }
HANDLER(f64reinterpret_i64) { nextop(); }
HANDLER(i32extend8_s)  { UNARY_OP(i32, (int32_t)(int8_t)); }
HANDLER(i32extend16_s) { UNARY_OP(i32, (int32_t)(int16_t)); }
HANDLER(i64extend8_s)  { UNARY_OP(i64, (int64_t)(int8_t)); }
HANDLER(i64extend16_s) { UNARY_OP(i64, (int64_t)(int16_t)); }
HANDLER(i64extend32_s) { UNARY_OP(i64, (int64_t)(int32_t)); }
HANDLER(ref_null) {
    read_leb128(iter);
    stack.push((void*)nullptr);
    nextop();
}
HANDLER(ref_is_null) {
    // note that funcref is also a full 0 value when null
    stack[-1].i32 = stack[-1].externref == nullptr;
    nextop();
}
HANDLER(ref_func) {
    uint32_t func_idx = read_leb128(iter);
    stack.push(&instance.functions[func_idx]);
    nextop();
}
// bitwise comparison applies to both
HANDLER(ref_eq) { BINARY_OP(externref, ==); }
HANDLER(multibyte) {
    uint8_t byte = *iter++;
#ifdef WASM_DEBUG
    std::cerr << "reading multibyte instruction " << multibyte_instructions[byte].c_str() << std::endl;        \
    std::cerr << "stack contents: ";                                       \
    for (WasmValue *p = instance.frame.locals; p < stack.unsafe_ptr(); p++) {       \
        std::cerr << p->u64 << " ";                                        \
    }                                                                      \
    std::cerr << std::endl << std::endl;                                   
#endif
    [[clang::musttail]] return fc_handlers[byte](instance, iter, stack, control_stack);
}
HANDLER(i32_trunc_sat_f32_s) { TRUNC_SAT(f32, i32); }
HANDLER(i32_trunc_sat_f32_u) { TRUNC_SAT(f32, u32); }
HANDLER(i32_trunc_sat_f64_s) { TRUNC_SAT(f64, i32); }
HANDLER(i32_trunc_sat_f64_u) { TRUNC_SAT(f64, u32); }
HANDLER(i64_trunc_sat_f32_s) { TRUNC_SAT(f32, i64); }
HANDLER(i64_trunc_sat_f32_u) { TRUNC_SAT(f32, u64); }
HANDLER(i64_trunc_sat_f64_s) { TRUNC_SAT(f64, i64); }
HANDLER(i64_trunc_sat_f64_u) { TRUNC_SAT(f64, u64); }
HANDLER(memory_init) {
    uint32_t seg_idx = read_leb128(iter);
    iter++;
    uint32_t size = stack.pop().u32;
    uint32_t src = stack.pop().u32;
    uint32_t dest = stack.pop().u32;
    instance.memory->copy_into(dest, src, instance.data_segments[seg_idx], size);
    nextop();
}
HANDLER(data_drop) {
    uint32_t seg_idx = read_leb128(iter);
    instance.data_segments[seg_idx].data = {};
    nextop();
}
HANDLER(memory_copy) {
    /* uint32_t mem_idx = */ read_leb128(iter);
    /* uint32_t mem_idx = */ read_leb128(iter);
    uint32_t size = stack.pop().u32;
    uint32_t src = stack.pop().u32;
    uint32_t dst = stack.pop().u32;
    instance.memory->memcpy(dst, src, size);
    nextop();
}
HANDLER(memory_fill) {
    /* uint32_t mem_idx = */ read_leb128(iter);
    uint32_t size = stack.pop().u32;
    uint32_t value = stack.pop().u32;
    uint32_t ptr = stack.pop().u32;
    instance.memory->memset(ptr, value, size);
    nextop();
}
HANDLER(table_init) {
    uint32_t seg_idx = read_leb128(iter);
    uint32_t table_idx = read_leb128(iter);
    uint32_t size = stack.pop().u32;
    uint32_t src = stack.pop().u32;
    uint32_t dest = stack.pop().u32;

    auto& table = instance.tables[table_idx];
    auto& element = instance.elements[seg_idx];
    table->copy_into(dest, src, element, size);
    nextop();
}
HANDLER(elem_drop) {
    uint32_t seg_idx = read_leb128(iter);
    instance.elements[seg_idx].elements.clear();
    nextop();
}
HANDLER(table_copy) {
    uint32_t dst_table = read_leb128(iter);
    uint32_t src_table = read_leb128(iter);
    uint32_t size = stack.pop().u32;
    uint32_t src = stack.pop().u32;
    uint32_t dst = stack.pop().u32;
    instance.tables[src_table]->memcpy(*instance.tables[dst_table], dst, src, size);
    nextop();
}
HANDLER(table_grow) {
    uint32_t table_idx = read_leb128(iter);
    uint32_t delta = stack.pop().u32;
    WasmValue init = stack.pop();
    stack.push(instance.tables[table_idx]->grow(delta, init));
    nextop();
}
HANDLER(table_size) {
    uint32_t table_idx = read_leb128(iter);
    stack.push(instance.tables[table_idx]->size());
    nextop();
}
HANDLER(table_fill) {
    uint32_t table_idx = read_leb128(iter);
    uint32_t size = stack.pop().u32;
    WasmValue value = stack.pop();
    uint32_t ptr = stack.pop().u32;
    instance.tables[table_idx]->memset(ptr, value, size);
    nextop();
}
// clang-format on

#undef UNARY_OP
#undef UNARY_FN
#undef BINARY_OP
#undef BINARY_FN
#undef LOAD
#undef STORE

Instance::~Instance() {
    assert(initial_stack.empty());
    assert(initial_control_stack.empty());
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
    // subtraction to avoid overflow
    if (delta > maximum - current) {
        return -1;
    }

    uint32_t new_current = current + delta;
    uint8_t *new_memory = (uint8_t *)realloc(memory, new_current * PAGE_SIZE);
    if (new_memory == NULL)
        return -1;
    memory = new_memory;
    std::memset(memory + current * PAGE_SIZE, 0, delta * PAGE_SIZE);

    uint32_t old_current = current;
    current = new_current;
    return old_current;
}

void WasmMemory::copy_into(uint32_t dest, uint32_t src, const Segment &segment,
                           uint32_t length) {
    if (static_cast<uint64_t>(dest) + length > current * PAGE_SIZE ||
        src + length > segment.data.size()) {
        trap("out of bounds memory access");
    }
    std::memcpy(memory + dest, segment.data.data() + src, length);
}

void WasmMemory::memcpy(uint32_t dst, uint32_t src, uint32_t length) {
    if (static_cast<uint64_t>(dst) + length > current * PAGE_SIZE ||
        static_cast<uint64_t>(src) + length > current * PAGE_SIZE) {
        trap("out of bounds memory access");
    }
    std::memmove(memory + dst, memory + src, length);
}

void WasmMemory::memset(uint32_t dst, uint8_t value, uint32_t length) {
    if (static_cast<uint64_t>(dst) + length > current * PAGE_SIZE) {
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
    if (delta == 0)
        return current;
    // subtraction to avoid overflow
    if (delta > maximum - current) {
        return -1;
    }

    uint32_t new_current = current + delta;
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
        trap("out of bounds table access");
    }
    return elements[idx];
}

void WasmTable::set(uint32_t idx, WasmValue value) {
    if (idx >= current) {
        trap("out of bounds table access");
    }
    elements[idx] = value;
}

void WasmTable::copy_into(uint32_t dst, uint32_t src,
                          const ElementSegment &segment, uint32_t length) {
    if (static_cast<uint64_t>(dst) + length > current ||
        src + length > segment.elements.size()) {
        trap("out of bounds table access");
    }
    std::memcpy(elements + dst, segment.elements.data() + src,
                length * sizeof(WasmValue));
}

void WasmTable::memcpy(WasmTable &dst_table, uint32_t dst, uint32_t src,
                       uint32_t length) {
    if (static_cast<uint64_t>(dst) + length > dst_table.current ||
        static_cast<uint64_t>(src) + length > this->current) {
        trap("out of bounds table access");
    }
    std::memmove(dst_table.elements + dst, elements + src,
                 length * sizeof(WasmValue));
}

void WasmTable::memset(uint32_t dst, WasmValue value, uint32_t length) {
    if (static_cast<uint64_t>(dst) + length > current) {
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
