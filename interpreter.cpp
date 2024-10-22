#include "interpreter.hpp"
#include "validator.hpp"
#include <limits>

namespace Mitey {
Instance::Instance(std::unique_ptr<uint8_t, void (*)(uint8_t *)> _bytes,
                   uint32_t length)
    : bytes(std::move(_bytes)),
      stack(static_cast<WasmValue *>(malloc(stack_size))), stack_start(stack) {

    // todo: use byte iterator or something
    uint8_t *iter = bytes.get();
    uint8_t *end = iter + length;
    assert(std::strncmp(reinterpret_cast<char *>(iter), "\0asm", 4) == 0);
    iter += 4;

    assert(*reinterpret_cast<uint32_t *>(iter) == 1);
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
            assert(*iter == 0x60);
            ++iter;

            Signature fn;

            uint32_t n_params = safe_read_leb128<uint32_t>(iter);
            fn.params.reserve(n_params);
            for (uint32_t j = 0; j < n_params; ++j) {
                assert(is_valtype(iter[j]));
                fn.params.push_back(static_cast<valtype>(iter[j]));
            }
            iter += n_params;

            uint32_t n_results = safe_read_leb128<uint32_t>(iter);
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

    // todo: table section
    if (iter != end && *iter == 4) {
        ++iter;
        uint32_t section_length = safe_read_leb128<uint32_t>(iter);
        iter += section_length;
    }

    skip_custom_section();

    // memory section
    if (iter != end && *iter == 5) {
        ++iter;
        /* uint32_t section_length = */ safe_read_leb128<uint32_t>(iter);

        uint32_t n_memories = safe_read_leb128<uint32_t>(iter);
        assert(n_memories == 1);

        // Limits are encoded with a preceding flag indicating whether a maximum
        // is present.
        uint32_t flags = safe_read_leb128<uint32_t>(iter);
        assert(flags == 0 || flags == 1);

        uint32_t initial = safe_read_leb128<uint32_t>(iter);
        uint32_t maximum =
            flags == 1 ? safe_read_leb128<uint32_t>(iter) : initial;

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
    if (iter != end && *iter == 7) {
        ++iter;
        /* uint32_t section_length = */ safe_read_leb128<uint32_t>(iter);
        uint32_t n_exports = safe_read_leb128<uint32_t>(iter);

        for (uint32_t i = 0; i < n_exports; ++i) {
            uint32_t name_len = safe_read_leb128<uint32_t>(iter);
            std::string name(reinterpret_cast<char *>(iter), name_len);
            iter += name_len;

            uint8_t desc = *iter++;
            assert(desc >= 0 && desc <= 3);
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

    // todo: element section
    if (iter != end && *iter == 9) {
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

        assert(n_functions == functions.size());

        for (FunctionInfo &fn : functions) {
            fn.locals = fn.type.params;

            uint32_t function_length = safe_read_leb128<uint32_t>(iter);
            uint8_t *start = iter;

            uint32_t n_local_decls = safe_read_leb128<uint32_t>(iter);
            while (n_local_decls--) {
                uint32_t n_locals = safe_read_leb128<uint32_t>(iter);
                uint8_t type = *iter++;
                assert(is_valtype(type));
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
        uint32_t section_length = safe_read_leb128<uint32_t>(iter);
        iter += section_length;
    }

    skip_custom_section();

    // todo: data count section
    if (iter != end && *iter == 12) {
        ++iter;
        uint32_t section_length = safe_read_leb128<uint32_t>(iter);
        iter += section_length;
    }

    skip_custom_section();

    Validator(*this).validate();

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
}

[[noreturn]] void trap(std::string message) {
    throw std::runtime_error(message);
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
        std::memcpy(target.stack, stack - target.arity,
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

#define LOAD(type)                                                             \
    {                                                                          \
        uint32_t align = 1 << *iter++;                                         \
        uint32_t offset = read_leb128(iter);                                   \
        stack[-1] = memory.load<type>(stack[-1].u32, offset, align);           \
        break;                                                                 \
    }

#define STORE(type, stacktype)                                                 \
    {                                                                          \
        stack -= 2;                                                            \
        uint32_t align = 1 << *iter++;                                         \
        uint32_t offset = read_leb128(iter);                                   \
        memory.store<type>(stack[1].u32, offset, align,                        \
                           static_cast<type>(stack[0].stacktype));             \
        break;                                                                 \
    }

    using enum Instruction;

    while (1) {
        uint8_t byte = *iter++;
#ifdef WASM_DEBUG
        printf("reading instruction %s at %ld\n", instructions[byte].c_str(),
               iter - bytes.get());
        printf("stack contents: ");
        for (WasmValue *p = stack_start; p < stack; ++p) {
            printf("%llu ", p->u64);
        }
        printf("\n\n");
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
                {stack - sn.results.size(), block_ends[iter],
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
                {stack - sn.results.size(), if_jumps[iter].end,
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
            brk(frame().control_stack.size());
            return;
        case call: {
            FunctionInfo &fn = functions[read_leb128(iter)];
            prepare_to_call(fn, iter);
            iter = fn.start;
            break;
        }
        case call_indirect:
            break;
        case drop:
            stack--;
            break;
        case select: {
            stack -= 2;
            stack[-1] = stack[-1].i32 ? stack[1] : stack[0];
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
        case i32load:      LOAD(uint32_t);
        case i64load:      LOAD(uint64_t);
        case f32load:      LOAD(float);
        case f64load:      LOAD(double);
        case i32load8_s:   LOAD(int8_t);
        case i32load8_u:   LOAD(uint8_t);
        case i32load16_s:  LOAD(int16_t);
        case i32load16_u:  LOAD(uint16_t);
        case i64load8_s:   LOAD(int8_t);
        case i64load8_u:   LOAD(uint8_t);
        case i64load16_s:  LOAD(int16_t);
        case i64load16_u:  LOAD(uint16_t);
        case i64load32_s:  LOAD(int32_t);
        case i64load32_u:  LOAD(uint32_t);
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
            // clang-format on
        };
    }

#undef UNARY_OP
#undef UNARY_FN
#undef BINARY_OP
#undef BINARY_FN
#undef LOAD
#undef STORE
} // namespace Mitey

// todo: this should check stack is the base pointer
// won't be necessary after validation is added
Instance::~Instance() {
    assert(stack == stack_start);
    free(stack_start);
}
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
