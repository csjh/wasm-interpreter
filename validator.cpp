#include "validator.hpp"

namespace Mitey {

void Validator::validate() {
    for (auto &fn : instance.functions) {
        current_fn = fn;
        control_stack.push_back(fn.type.results);

        validate(fn.start, fn.type, true);

        assert(control_stack.size() == 1);
        control_stack.clear();
    }
}

void Validator::validate(uint8_t *&iter, const Signature &signature,
                         bool is_func) {
    std::vector<valtype> stack =
        is_func ? std::vector<valtype>{} : signature.params;

    auto push = [&](valtype ty) { stack.push_back(ty); };
    auto push_many = [&](const std::vector<valtype> &values) {
        stack.insert(stack.end(), values.begin(), values.end());
    };
    auto pop = [&](valtype ty) {
        assert(!stack.empty());
        assert(stack.back() == ty);
        stack.pop_back();
    };
    auto pop_many = [&](const std::vector<valtype> &expected) {
        assert(expected.size() <= stack.size());
        assert(std::equal(expected.begin(), expected.end(),
                          stack.end() - expected.size()));
        stack.erase(stack.end() - expected.size(), stack.end());
    };
    auto apply = [&](Signature signature) {
        pop_many(signature.params);
        push_many(signature.results);
    };
    auto check_br = [&](uint32_t depth) {
        assert(depth < control_stack.size());
        auto &expected_at_target =
            control_stack[control_stack.size() - depth - 1];
        assert(expected_at_target.size() <= stack.size());
        assert(std::equal(expected_at_target.begin(), expected_at_target.end(),
                          stack.end() - expected_at_target.size()));
    };

#define LOAD(type, stacktype)                                                  \
    {                                                                          \
        uint32_t align = 1 << safe_read_leb128<uint32_t>(iter);                \
        assert(align <= 8 * sizeof(type));                                     \
        uint32_t offset = safe_read_leb128<uint32_t>(iter);                    \
        apply({{valtype::i32}, {stacktype}});                                  \
        break;                                                                 \
    }

#define STORE(type, stacktype)                                                 \
    {                                                                          \
        uint32_t align = 1 << safe_read_leb128<uint32_t>(iter);                \
        assert(align <= 8 * sizeof(type));                                     \
        uint32_t offset = safe_read_leb128<uint32_t>(iter);                    \
        apply({{valtype::i32, stacktype}, {}});                                \
        break;                                                                 \
    }

    using enum Instruction;
    while (1) {
        uint8_t byte = *iter++;
        assert(is_instruction(byte));
        printf("reading instruction %#04x\n", byte);
        switch (static_cast<Instruction>(byte)) {
        case unreachable:
            break;
        case nop:
            break;
        case block: {
            Signature signature = read_blocktype(iter);

            pop_many(signature.params);

            control_stack.push_back(signature.results);
            validate(iter, signature);
            control_stack.pop_back();

            push_many(signature.results);
            break;
        }
        case loop: {
            Signature signature = read_blocktype(iter);

            pop_many(signature.params);

            control_stack.push_back(signature.params);
            validate(iter, signature);
            control_stack.pop_back();

            push_many(signature.results);
            break;
        }
        case if_: {
            pop(valtype::i32);

            Signature signature = read_blocktype(iter);

            pop_many(signature.params);

            control_stack.push_back(signature.results);
            validate(iter, signature);
            // validate else branch if previous instruction was else
            if (iter[-1] == static_cast<uint8_t>(else_))
                validate(iter, signature);
            control_stack.pop_back();

            push_many(signature.results);
            break;
        }
        // else is basically an end to an if
        case else_:
        case end:
            pop_many(signature.results);
            return;
        case br: {
            check_br(safe_read_leb128<uint32_t>(iter));
            break;
        }
        case br_if: {
            pop(valtype::i32);
            uint32_t depth = safe_read_leb128<uint32_t>(iter);
            check_br(depth);
            break;
        }
        case br_table: {
            pop(valtype::i32);
            uint32_t n_targets = safe_read_leb128<uint32_t>(iter);

            // <= because there's an extra for the default target
            for (uint32_t i = 0; i <= n_targets; ++i) {
                uint32_t target = safe_read_leb128<uint32_t>(iter);
                check_br(target);
            }
            break;
        }
        case return_:
            check_br(control_stack.size() - 1);
            break;
        case call: {
            uint32_t fn_idx = safe_read_leb128<uint32_t>(iter);
            assert(fn_idx < instance.functions.size());

            FunctionInfo &fn = instance.functions[fn_idx];
            apply(fn.type);
            break;
        }
        case call_indirect: {
            pop(valtype::i32);

            uint32_t table_idx = safe_read_leb128<uint32_t>(iter);
            assert(table_idx == 0);

            uint32_t type_idx = safe_read_leb128<uint32_t>(iter);
            assert(type_idx < instance.types.size());
            apply(instance.types[type_idx]);
            break;
        }
        case drop:
            assert(!stack.empty());
            stack.pop_back();
            break;
        case select: {
            assert(stack.size() >= 3);
            // first pop the condition
            pop(valtype::i32);
            valtype ty = stack.back();
            // then apply the dynamic type
            apply({{ty, ty}, {ty}});
            break;
        }
        case localget: {
            uint32_t local_idx = safe_read_leb128<uint32_t>(iter);
            assert(local_idx < current_fn.locals.size());
            push(current_fn.locals[local_idx]);
            break;
        }
        case localset: {
            uint32_t local_idx = safe_read_leb128<uint32_t>(iter);
            assert(local_idx < current_fn.locals.size());
            pop(current_fn.locals[local_idx]);
            break;
        }
        case localtee: {
            uint32_t local_idx = safe_read_leb128<uint32_t>(iter);
            assert(local_idx < current_fn.locals.size());
            pop(current_fn.locals[local_idx]);
            push(current_fn.locals[local_idx]);
            break;
        }
        case globalget: {
            uint32_t global_idx = safe_read_leb128<uint32_t>(iter);
            assert(global_idx < instance.globals.size());
            push(instance.globals[global_idx].type);
            break;
        }
        case globalset: {
            uint32_t global_idx = safe_read_leb128<uint32_t>(iter);
            assert(global_idx < instance.globals.size());
            pop(instance.globals[global_idx].type);
            break;
        }
        case memorysize: {
            uint32_t mem_idx = safe_read_leb128<uint32_t>(iter);
            assert(mem_idx == 0);
            push(valtype::i32);
            break;
        }
        case memorygrow: {
            uint32_t mem_idx = safe_read_leb128<uint32_t>(iter);
            assert(mem_idx == 0);
            apply({{valtype::i32}, {valtype::i32}});
            break;
        }
        case i32const:
            safe_read_leb128<uint32_t>(iter);
            push(valtype::i32);
            break;
        case i64const:
            safe_read_leb128<uint64_t>(iter);
            push(valtype::i64);
            break;
        case f32const: {
            iter += sizeof(float);
            push(valtype::f32);
            break;
        }
        case f64const:
            iter += sizeof(double);
            push(valtype::f64);
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
        default: assert(false);
            // clang-format on
        };
    }

    assert(false);
}

} // namespace Mitey