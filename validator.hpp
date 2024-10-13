#include "interpreter.hpp"

namespace Mitey {

class Validator {
    Instance &instance;
    FunctionInfo current_fn;
    std::vector<std::vector<valtype>> control_stack;

    void validate(uint8_t *&iter, const std::vector<valtype> &expected);

    Signature read_blocktype(uint8_t *&iter) {
        if (*iter == static_cast<uint8_t>(valtype::empty)) {
            return {{}, {}};
        } else if (is_valtype(*iter)) {
            return {{}, {static_cast<valtype>(*iter)}};
        } else {
            int64_t n = -safe_read_sleb128<int64_t, 33>(iter);
            assert(n >= 0);
            assert(n < instance.types.size());
            return instance.types[n];
        }
    }

  public:
    Validator(Instance &instance) : instance(instance) {}

    void validate();
};

} // namespace Mitey
