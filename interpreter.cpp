#include "interpreter.hpp"
#include "spec.hpp"
#include "validator.hpp"
#include <iostream>
#include <limits>

#ifdef WASM_DEBUG
#include <iostream>
#endif

namespace mitey {
std::tuple<uint32_t, uint32_t> get_limits(uint8_t *&iter) {
    uint32_t flags = safe_read_leb128<uint32_t>(iter);
    if (flags != 0 && flags != 1) {
        throw malformed_error("invalid flags");
    }
    uint32_t initial = safe_read_leb128<uint32_t>(iter);
    uint32_t maximum = flags == 1 ? safe_read_leb128<uint32_t>(iter)
                                  : std::numeric_limits<uint32_t>::max();
    return {initial, maximum};
}

Instance::Instance(std::unique_ptr<uint8_t, void (*)(uint8_t *)> _bytes,
                   uint32_t length)
    : bytes(std::move(_bytes)),
      stack(static_cast<WasmValue *>(malloc(stack_size))), stack_start(stack) {

    // todo: use byte iterator or something
    uint8_t *iter = bytes.get();
    uint8_t *end = iter + length;
    if (std::strncmp(reinterpret_cast<char *>(iter), "\0asm", 4) != 0) {
        throw malformed_error("invalid magic number");
    }
    iter += 4;

    if (*reinterpret_cast<uint32_t *>(iter) != 1) {
        throw malformed_error("invalid version");
    }
    iter += sizeof(uint32_t);

    auto skip_custom_section = [&]() {
        while (iter != end && *iter == 0) [[unlikely]] {
            ++iter;
            uint32_t section_length = safe_read_leb128<uint32_t>(iter);
            iter += section_length;
        }
    };

    skip_custom_section();

    // type section
    if (iter != end && *iter == 1) {
        ++iter;
        /* uint32_t section_length = */ safe_read_leb128<uint32_t>(iter);
        uint32_t n_types = safe_read_leb128<uint32_t>(iter);

        types.reserve(n_types);

        for (uint32_t i = 0; i < n_types; ++i) {
            if (*iter != 0x60) {
                throw malformed_error("invalid function type");
            }
            ++iter;

            Signature fn{{}, {}, i};

            uint32_t n_params = safe_read_leb128<uint32_t>(iter);
            fn.params.reserve(n_params);
            for (uint32_t j = 0; j < n_params; ++j) {
                if (!is_valtype(iter[j])) {
                    throw malformed_error("invalid parameter type");
                }
                fn.params.push_back(static_cast<valtype>(iter[j]));
            }
            iter += n_params;

            uint32_t n_results = safe_read_leb128<uint32_t>(iter);
            fn.results.reserve(n_results);
            for (uint32_t j = 0; j < n_results; ++j) {
                if (!is_valtype(iter[j])) {
                    throw malformed_error("invalid result type");
                }
                fn.results.push_back(static_cast<valtype>(iter[j]));
            }
            iter += n_results;

            types.emplace_back(fn);
        }
    }

    skip_custom_section();

    // todo: import section
    if (iter != end && *iter == 2) {
        ++iter;
        uint32_t section_length = safe_read_leb128<uint32_t>(iter);
        iter += section_length;
    }

    skip_custom_section();

    // function type section
    if (iter != end && *iter == 3) {
        ++iter;
        /* uint32_t section_length = */ safe_read_leb128<uint32_t>(iter);
        uint32_t n_functions = safe_read_leb128<uint32_t>(iter);

        functions.reserve(n_functions);

        for (uint32_t i = 0; i < n_functions; ++i) {
            uint32_t type_idx = safe_read_leb128<uint32_t>(iter);
            functions.emplace_back(FunctionInfo{nullptr, types[type_idx], {}});
        }
    }

    skip_custom_section();

    // table section
    if (iter != end && *iter == 4) {
        ++iter;
        /* uint32_t section_length = */ safe_read_leb128<uint32_t>(iter);

        uint32_t n_tables = safe_read_leb128<uint32_t>(iter);
        tables.reserve(n_tables);

        for (uint32_t i = 0; i < n_tables; ++i) {
            uint8_t elem_type = *iter++;
            if (!is_reftype(elem_type)) {
                throw malformed_error("invalid table element type");
            }

            auto [initial, maximum] = get_limits(iter);
            tables.emplace_back(
                WasmTable{static_cast<valtype>(elem_type), initial, maximum});
        }
    }

    skip_custom_section();

    // memory section
    if (iter != end && *iter == 5) {
        ++iter;
        /* uint32_t section_length = */ safe_read_leb128<uint32_t>(iter);

        uint32_t n_memories = safe_read_leb128<uint32_t>(iter);
        if (n_memories > 1) {
            throw malformed_error("multiple memories");
        }

        auto [initial, maximum] = get_limits(iter);
        new (&memory) WasmMemory(initial, maximum);
    }

    skip_custom_section();

    // global section
    if (iter != end && *iter == 6) {
        ++iter;
        /* uint32_t section_length = */ safe_read_leb128<uint32_t>(iter);
        uint32_t n_globals = safe_read_leb128<uint32_t>(iter);

        globals.reserve(n_globals);

        for (uint32_t i = 0; i < n_globals; ++i) {
            uint8_t maybe_type = *iter++;
            if (!is_valtype(maybe_type)) {
                throw malformed_error("invalid global type");
            }
            valtype type = static_cast<valtype>(maybe_type);

            uint8_t maybe_mut = *iter++;
            if (!is_mut(maybe_mut)) {
                throw malformed_error("invalid global mutability");
            }
            mut global_mut = static_cast<mut>(maybe_mut);

            globals.emplace_back(
                WasmGlobal{type, global_mut, interpret_const(iter)});
        }
    }

    skip_custom_section();

    // export section
    if (iter != end && *iter == 7) {
        ++iter;
        /* uint32_t section_length = */ safe_read_leb128<uint32_t>(iter);
        uint32_t n_exports = safe_read_leb128<uint32_t>(iter);

        for (uint32_t i = 0; i < n_exports; ++i) {
            uint32_t name_len = safe_read_leb128<uint32_t>(iter);
            std::string name(reinterpret_cast<char *>(iter), name_len);
            iter += name_len;

            uint8_t desc = *iter++;
            if (desc < 0 || desc > 3) {
                throw malformed_error("invalid export description");
            }
            ExportDesc export_desc = static_cast<ExportDesc>(desc);

            uint32_t idx = safe_read_leb128<uint32_t>(iter);

            exports[name] = {export_desc, idx};
        }
    }

    skip_custom_section();

    // start section
    uint32_t start = std::numeric_limits<uint32_t>::max();
    if (iter != end && *iter == 8) {
        ++iter;
        /* uint32_t section_length = */ safe_read_leb128<uint32_t>(iter);
        start = safe_read_leb128<uint32_t>(iter);
    }

    skip_custom_section();

    // element section
    if (iter != end && *iter == 9) {
        ++iter;
        /* uint32_t section_length = */ safe_read_leb128<uint32_t>(iter);
        uint32_t n_elements = safe_read_leb128<uint32_t>(iter);

        elements.reserve(n_elements);

        for (uint32_t i = 0; i < n_elements; i++) {
            uint8_t flags = *iter++;
            if (flags & ~0b111) {
                throw malformed_error("invalid element flags");
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
                            throw malformed_error("invalid reftype");
                        }
                        uint32_t n_elements = safe_read_leb128<uint32_t>(iter);
                        for (uint32_t j = 0; j < n_elements; j++) {
                            interpret_const(iter);
                        }
                    } else {
                        // flags = 3
                        // characteristics: declarative, elem kind + indices
                        uint8_t elemkind = *iter++;
                        if (elemkind != 0) {
                            throw malformed_error("invalid elemkind");
                        }
                        uint32_t n_elements = safe_read_leb128<uint32_t>(iter);
                        for (uint32_t j = 0; j < n_elements; j++) {
                            uint32_t elem_idx =
                                safe_read_leb128<uint32_t>(iter);
                            if (elem_idx >= functions.size()) {
                                throw malformed_error("invalid element index");
                            }
                        }
                    }
                } else {
                    if (flags & 0b100) {
                        // flags = 5
                        // characteristics: passive, elem type + exprs
                        uint8_t reftype = *iter++;
                        if (!is_reftype(reftype)) {
                            throw malformed_error("invalid reftype");
                        }
                        uint32_t n_elements = safe_read_leb128<uint32_t>(iter);
                        std::vector<WasmValue> elem{n_elements};
                        for (uint32_t j = 0; j < n_elements; j++) {
                            WasmValue el = interpret_const(iter);
                            elem.push_back(el);
                        }
                        elements.emplace_back(elem);
                    } else {
                        // flags = 1
                        // characteristics: passive, elem kind + indices
                        uint8_t elemkind = *iter++;
                        if (elemkind != 0) {
                            throw malformed_error("invalid elemkind");
                        }
                        uint32_t n_elements = safe_read_leb128<uint32_t>(iter);
                        std::vector<WasmValue> elem{n_elements};
                        for (uint32_t j = 0; j < n_elements; j++) {
                            uint32_t elem_idx =
                                safe_read_leb128<uint32_t>(iter);
                            if (elem_idx >= functions.size()) {
                                throw malformed_error("invalid element index");
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

                uint32_t offset = interpret_const(iter).u32;
                if (offset >= tables[table_idx].size()) {
                    throw malformed_error("invalid table offset");
                }

                uint32_t n_elements = safe_read_leb128<uint32_t>(iter);
                std::vector<WasmValue> elem{n_elements};
                if (flags & 0b100) {
                    // flags = 4 or 6
                    // characteristics: active, elem type + exprs
                    if (flags & 0b10) {
                        uint8_t reftype = *iter++;
                        if (!is_reftype(reftype)) {
                            throw malformed_error("invalid reftype");
                        }
                    }
                    for (uint32_t j = 0; j < n_elements; j++) {
                        WasmValue el = interpret_const(iter);
                        elem.push_back(el);
                        tables[table_idx].set(offset + j, el);
                    }
                } else {
                    if (flags & 0b10) {
                        uint8_t elemkind = *iter++;
                        if (elemkind != 0) {
                            throw malformed_error("invalid elemkind");
                        }
                    }
                    // flags = 0 or 2
                    // characteristics: active, elem kind + indices
                    for (uint32_t j = 0; j < n_elements; j++) {
                        uint32_t elem_idx = safe_read_leb128<uint32_t>(iter);
                        if (elem_idx >= functions.size()) {
                            throw malformed_error("invalid element index");
                        }
                        WasmValue funcref = Funcref{
                            functions[elem_idx].type.typeidx, true, elem_idx};
                        elem.push_back(funcref);
                        tables[table_idx].set(offset + j, funcref);
                    }
                }
                elements.emplace_back(elem);
            }
        }
    }

    skip_custom_section();

    // data count section
    if (iter != end && *iter == 12) {
        ++iter;
        uint32_t section_length = safe_read_leb128<uint32_t>(iter);
        iter += section_length;
    }

    skip_custom_section();

    // code section
    if (iter != end && *iter == 10) {
        ++iter;
        /* uint32_t section_length = */ safe_read_leb128<uint32_t>(iter);
        uint32_t n_functions = safe_read_leb128<uint32_t>(iter);

        if (n_functions != functions.size()) {
            throw malformed_error("function count mismatch");
        }

        for (FunctionInfo &fn : functions) {
            fn.locals = fn.type.params;

            uint32_t function_length = safe_read_leb128<uint32_t>(iter);
            uint8_t *start = iter;

            uint32_t n_local_decls = safe_read_leb128<uint32_t>(iter);
            while (n_local_decls--) {
                uint32_t n_locals = safe_read_leb128<uint32_t>(iter);
                uint8_t type = *iter++;
                if (!is_valtype(type)) {
                    throw malformed_error("invalid local type");
                }
                while (n_locals--) {
                    fn.locals.push_back(static_cast<valtype>(type));
                }
            }
            fn.start = iter;

            iter = start + function_length;
        }
    }

    skip_custom_section();

    // todo: data section
    if (iter != end && *iter == 11) {
        ++iter;
        /* uint32_t section_length = */ safe_read_leb128<uint32_t>(iter);
        uint32_t n_data = safe_read_leb128<uint32_t>(iter);

        for (uint32_t i = 0; i < n_data; i++) {
            uint32_t segment_flag = *iter++;
            if (segment_flag & ~0b11) {
                throw malformed_error("invalid data segment flag");
            }

            uint32_t memidx =
                segment_flag & 0b10 ? safe_read_leb128<uint32_t>(iter) : 0;

            if (memidx != 0) {
                throw malformed_error("non-zero memory index");
            }

            if (segment_flag & 1) {
                // passive segment

                uint32_t data_length = safe_read_leb128<uint32_t>(iter);
                std::vector<uint8_t> data(data_length);
                std::memcpy(data.data(), iter, data_length);
                iter += data_length;

                data_segments.emplace_back(Segment{memidx, std::move(data)});
            } else {
                // active segment

                uint32_t offset = interpret_const(iter).u32;
                if (offset >= memory.size() * WasmMemory::PAGE_SIZE) {
                    throw malformed_error("invalid memory offset");
                }

                uint32_t data_length = safe_read_leb128<uint32_t>(iter);
                std::vector<uint8_t> data(data_length);
                std::memcpy(data.data(), iter, data_length);
                iter += data_length;

                memory.copy_into(offset, data.data(), data_length);

                data_segments.emplace_back(Segment{memidx, std::move(data)});
            }
        }
    }

    skip_custom_section();

    Validator(*this, data_segments.size()).validate();

    if (start != std::numeric_limits<uint32_t>::max()) {
        execute<void (*)()>(start);
    }
}

void Instance::prepare_to_call(const FunctionInfo &fn, uint8_t *return_to) {
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

    constexpr size_t MAX_DEPTH = 1'000'000;
    if (frames.size() > MAX_DEPTH) {
        trap("call stack exhausted");
    }
}

// constant expressions (including extended const expression proposal)
WasmValue Instance::interpret_const(uint8_t *&iter) {
#define OP(ty, op)                                                             \
    {                                                                          \
        stack[-1].ty = stack[-1].ty op stack[0].ty;                            \
        stack--;                                                               \
        break;                                                                 \
    }
#define I32_OP(op) OP(i32, op)
#define I64_OP(op) OP(i64, op)

    while (1) {
        uint8_t byte = *iter++;
        using enum Instruction;
        if (static_cast<Instruction>(byte) == end) {
            break;
        }
        switch (static_cast<Instruction>(byte)) {
        case i32const:
            *stack++ = safe_read_leb128<int32_t>(iter);
            break;
        case i64const:
            *stack++ = safe_read_leb128<int64_t>(iter);
            break;
        case f32const:
            *stack++ = *reinterpret_cast<float *>(iter);
            iter += sizeof(float);
            break;
        case f64const:
            *stack++ = *reinterpret_cast<double *>(iter);
            iter += sizeof(double);
            break;
        case globalget: {
            uint32_t global_idx = safe_read_leb128<uint32_t>(iter);
            if (global_idx >= globals.size()) {
                throw malformed_error("invalid global index");
            }
            *stack++ = globals[global_idx].value;
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
        case ref_null:
            *stack++ = nullptr;
            break;
        case ref_func: {
            uint32_t func_idx = safe_read_leb128<uint32_t>(iter);
            if (func_idx >= functions.size()) {
                throw malformed_error("invalid function index");
            }
            *stack++ =
                Funcref{functions[func_idx].type.typeidx, true, func_idx};
            break;
        }
        default:
            throw malformed_error("invalid instruction in const expression");
        }
    }

#undef OP
#undef I32_OP
#undef I64_OP

    if (stack - stack_start != 1) {
        throw malformed_error("Incorrect number of results");
    }

    return *--stack;
}

void Instance::interpret(uint8_t *iter) {
    auto push = [&](WasmValue value) { *stack++ = value; };
    auto pop = [&]() { return *--stack; };

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
// todo: am i actually supposed to handle j1/j2 = 2^(n-1)
#define IDIV(type)                                                             \
    {                                                                          \
        stack--;                                                               \
        if (stack[0].type == 0) {                                              \
            trap("integer divide by zero");                                    \
        }                                                                      \
        using Ty = decltype(stack[-1].type);                                   \
        if (stack[0].type == static_cast<Ty>(-1) &&                            \
            stack[-1].type == std::numeric_limits<Ty>::min()) {                \
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

#define LOAD(type, memtype)                                                    \
    {                                                                          \
        uint32_t align = 1 << *iter++;                                         \
        uint32_t offset = read_leb128(iter);                                   \
        stack[-1].type = memory.load<memtype>(stack[-1].u32, offset, align);   \
        break;                                                                 \
    }

#define STORE(type, stacktype)                                                 \
    {                                                                          \
        stack -= 2;                                                            \
        uint32_t align = 1 << *iter++;                                         \
        uint32_t offset = read_leb128(iter);                                   \
        memory.store<type>(stack[0].u32, offset, align,                        \
                           static_cast<type>(stack[1].stacktype));             \
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
            frame().control_stack.push_back(
                {stack - sn.params.size(), if_jumps[iter].end,
                 static_cast<uint32_t>(sn.results.size())});
            if (!pop().i32)
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
            prepare_to_call(fn, iter);
            iter = fn.start;
            break;
        }
        case call_indirect: {
            uint32_t type_idx = read_leb128(iter);
            uint32_t table_idx = read_leb128(iter);
            uint32_t elem_idx = pop().u32;

            Funcref funcref = tables[table_idx].get(elem_idx);
            if (!funcref.nonnull) {
                trap("indirect call to null");
            }
            if (funcref.typeidx != type_idx) {
                trap("indirect call type mismatch");
            }
            FunctionInfo &fn = functions[funcref.funcidx];
            prepare_to_call(fn, iter);
            iter = fn.start;
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
            push(tables[read_leb128(iter)].get(pop().u32));
            break;
        case tableset:
            tables[read_leb128(iter)].set(pop().u32, pop());
            break;
        case globalget:
            push(globals[read_leb128(iter)].value);
            break;
        case globalset:
            globals[read_leb128(iter)].value = pop();
            break;
        case memorysize: {
            /* uint32_t mem_idx = */ read_leb128(iter);
            push(memory.size());
            break;
        }
        case memorygrow: {
            /* uint32_t mem_idx = */ read_leb128(iter);
            stack[-1].u32 = memory.grow(stack[-1].u32);
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
                    if (dest + size > memory.size() * WasmMemory::PAGE_SIZE) {
                        trap("out of bounds memory access");
                    }
                    if (offset + size > data_segments[seg_idx].data.size()) {
                        trap("offset outside of data segment");
                    }
                    memory.copy_into(dest, data_segments[seg_idx].data.data() + offset, size);
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
                    memory.memcpy(dst, src, size);
                    break;
                }
                case memory_fill: {
                    uint32_t value = pop().u32;
                    uint32_t ptr = pop().u32;
                    uint32_t size = pop().u32;
                    memory.memset(ptr, value, size);
                    break;
                }
                case table_init: {
                    uint32_t table_idx = read_leb128(iter);
                    uint32_t seg_idx = read_leb128(iter);
                    uint32_t size = pop().u32;
                    uint32_t offset = pop().u32;
                    uint32_t dest = pop().u32;

                    WasmTable& table = tables[table_idx];
                    if (dest + size > table.size()) {
                        trap("out of bounds memory access");
                    }

                    std::vector<WasmValue>& element = elements[seg_idx];
                    if (offset + size > element.size()) {
                        trap("offset outside of data segment");
                    }

                    table.copy_into(dest, element.data() + offset, size);
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
                    tables[dst].memcpy(dst, src, size);
                    break;
                }
                case table_grow: {
                    uint32_t table_idx = read_leb128(iter);
                    WasmValue init = pop();
                    uint32_t delta = pop().u32;
                    stack[-1].u32 = tables[table_idx].grow(delta, init);
                    break;
                }
                case table_size: {
                    uint32_t table_idx = read_leb128(iter);
                    push(tables[table_idx].size());
                    break;
                }
                case table_fill: {
                    WasmValue value = pop();
                    uint32_t ptr = pop().u32;
                    uint32_t size = pop().u32;
                    uint32_t table_idx = read_leb128(iter);
                    tables[table_idx].memset(ptr, value, size);
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
      current(initial), maximum(maximum) {}

WasmMemory::~WasmMemory() {
    if (memory) {
        free(memory);
    }
}

uint32_t WasmMemory::size() { return current; }

uint32_t WasmMemory::grow(uint32_t delta) {
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

uint32_t WasmTable::size() { return current; }

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
