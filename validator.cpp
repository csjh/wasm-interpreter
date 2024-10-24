#include "validator.hpp"

namespace mitey {

static inline void _ensure(bool condition, const std::string &expr, int line,
                           const std::string &file, const std::string &msg) {
    if (!condition) [[unlikely]] {
        throw validation_error("validation error: " + msg + " (" + expr + ") " +
                               file + ":" + std::to_string(line));
    }
}

#define ensure(condition, msg)                                                 \
    _ensure(condition, #condition, __LINE__, __FILE__, msg)

void Validator::validate() {
    for (const auto &fn : instance.functions) {
        current_fn = fn;
        control_stack.push_back(fn.type.results);

        uint8_t *iter = fn.start;
        validate(iter, fn.type, true);

        ensure(control_stack.size() == 1,
               "control stack not empty at end of function");
        control_stack.clear();
    }
}

class WasmStack : protected std::vector<valtype> {
    bool polymorphized = false;

  public:
    bool operator==(const std::vector<valtype> &rhs) {
        pop(rhs);
        return polymorphized || empty();
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
        ensure(expected.size() <= size(), "not enough values on stack");

        // due to stack polymorphism there might only be a few actual types on
        // the stack
        unsigned long materialized =
            std::min(std::vector<valtype>::size(), expected.size());
        ensure(std::equal(expected.rbegin(), expected.rbegin() + materialized,
                          rbegin()),
               "values on stack don't match expected");
        erase(end() - materialized, end());
    }

    bool empty() const {
        return !polymorphized && std::vector<valtype>::empty();
    }

    valtype back() const {
        ensure(!empty(), "stack is empty");
        // default to i32, shouldn't really matter
        return std::vector<valtype>::empty() && polymorphized
                   ? valtype::i32
                   : std::vector<valtype>::back();
    }

    unsigned long size() const {
        return polymorphized ? static_cast<unsigned long>(-1)
                             : std::vector<valtype>::size();
    }
};

void Validator::validate(uint8_t *&iter, const Signature &signature,
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
        ensure(depth < control_stack.size(), "invalid depth");
        auto &expected_at_target =
            control_stack[control_stack.size() - depth - 1];
        stack.pop(expected_at_target);
        stack.push(expected_at_target);
    };

#define LOAD(type, stacktype)                                                  \
    {                                                                          \
        uint32_t align = 1 << safe_read_leb128<uint32_t>(iter);                \
        ensure(align <= 8 * sizeof(type), "invalid alignment");                \
        /* uint32_t offset = */ safe_read_leb128<uint32_t>(iter);              \
        apply({{valtype::i32}, {stacktype}});                                  \
        break;                                                                 \
    }

#define STORE(type, stacktype)                                                 \
    {                                                                          \
        uint32_t align = 1 << safe_read_leb128<uint32_t>(iter);                \
        ensure(align <= 8 * sizeof(type), "invalid alignment");                \
        /* uint32_t offset = */ safe_read_leb128<uint32_t>(iter);              \
        apply({{valtype::i32, stacktype}, {}});                                \
        break;                                                                 \
    }

    using enum Instruction;
    while (1) {
        uint8_t byte = *iter++;
        ensure(is_instruction(byte), "invalid instruction");
        switch (static_cast<Instruction>(byte)) {
        case unreachable:
            stack.polymorphize();
            break;
        case nop:
            break;
        case block: {
            Signature signature = instance.read_blocktype(iter);

            stack.pop(signature.params);

            uint8_t *block_start = iter;

            control_stack.push_back(signature.results);
            validate(iter, signature);
            control_stack.pop_back();

            instance.block_ends[block_start] = iter;

            stack.push(signature.results);
            break;
        }
        case loop: {
            Signature signature = instance.read_blocktype(iter);

            stack.pop(signature.params);

            control_stack.push_back(signature.params);
            validate(iter, signature);
            control_stack.pop_back();

            stack.push(signature.results);
            break;
        }
        case if_: {
            stack.pop(valtype::i32);

            Signature signature = instance.read_blocktype(iter);

            stack.pop(signature.params);

            uint8_t *if_start = iter;

            control_stack.push_back(signature.results);
            validate(iter, signature);
            uint8_t *else_start = iter;
            // validate else branch if previous instruction was else
            if (iter[-1] == static_cast<uint8_t>(else_))
                validate(iter, signature);
            control_stack.pop_back();

            instance.if_jumps[if_start] = {else_start, iter};

            stack.push(signature.results);
            break;
        }
        // else is basically an end to an if
        case else_:
        case end:
            ensure(stack == signature.results, "stack doesn't match signature");
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

            // <= because there's an extra for the default target
            for (uint32_t i = 0; i <= n_targets; ++i) {
                uint32_t target = safe_read_leb128<uint32_t>(iter);
                check_br(target);
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
            ensure(fn_idx < instance.functions.size(),
                   "invalid function index");

            FunctionInfo &fn = instance.functions[fn_idx];
            apply(fn.type);
            break;
        }
        case call_indirect: {
            stack.pop(valtype::i32);

            uint32_t type_idx = safe_read_leb128<uint32_t>(iter);
            ensure(type_idx < instance.types.size(), "invalid type index");

            uint32_t table_idx = safe_read_leb128<uint32_t>(iter);
            ensure(table_idx == 0, "invalid table index");

            apply(instance.types[type_idx]);
            break;
        }
        case drop:
            ensure(!stack.empty(), "stack is empty");
            stack.pop(stack.back());
            break;
        case select: {
            ensure(stack.size() >= 3, "not enough values on stack");
            // first pop the condition
            stack.pop(valtype::i32);
            valtype ty = stack.back();
            // then apply the dynamic type
            apply({{ty, ty}, {ty}});
            break;
        }
        case localget: {
            uint32_t local_idx = safe_read_leb128<uint32_t>(iter);
            ensure(local_idx < current_fn.locals.size(), "invalid local index");
            valtype local_ty = current_fn.locals[local_idx];
            apply({{}, {local_ty}});
            break;
        }
        case localset: {
            uint32_t local_idx = safe_read_leb128<uint32_t>(iter);
            ensure(local_idx < current_fn.locals.size(), "invalid local index");
            valtype local_ty = current_fn.locals[local_idx];
            apply({{local_ty}, {}});
            break;
        }
        case localtee: {
            uint32_t local_idx = safe_read_leb128<uint32_t>(iter);
            ensure(local_idx < current_fn.locals.size(), "invalid local index");
            valtype locaL_ty = current_fn.locals[local_idx];
            apply({{locaL_ty}, {locaL_ty}});
            break;
        }
        case globalget: {
            uint32_t global_idx = safe_read_leb128<uint32_t>(iter);
            ensure(global_idx < instance.globals.size(),
                   "invalid global index");
            valtype global_ty = instance.globals[global_idx].type;
            apply({{}, {global_ty}});
            break;
        }
        case globalset: {
            uint32_t global_idx = safe_read_leb128<uint32_t>(iter);
            ensure(global_idx < instance.globals.size(),
                   "invalid global index");
            valtype global_ty = instance.globals[global_idx].type;
            apply({{global_ty}, {}});
            break;
        }
        case memorysize: {
            uint32_t mem_idx = safe_read_leb128<uint32_t>(iter);
            ensure(mem_idx == 0, "invalid memory index");
            apply({{}, {valtype::i32}});
            break;
        }
        case memorygrow: {
            uint32_t mem_idx = safe_read_leb128<uint32_t>(iter);
            ensure(mem_idx == 0, "invalid memory index");
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
        default: ensure(false, "unimplemented instruction");
            // clang-format on
        };
    }

    ensure(false, "unreachable");
}

#undef ensure

} // namespace mitey
