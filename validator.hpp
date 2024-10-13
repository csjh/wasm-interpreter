#include "interpreter.hpp"

namespace Mitey {

class Validator {
    Instance &instance;
    FunctionInfo current_fn;
    std::vector<std::vector<valtype>> control_stack;

    void validate(uint8_t *&iter, const std::vector<valtype> &expected);

    Signature from_blocktype(int64_t n) {
        if (n == static_cast<uint8_t>(valtype::empty)) {
            return {{}, {}};
        } else if (is_valtype(n)) {
            return {{}, {static_cast<valtype>(n)}};
        } else {
            return instance.types[n];
        }
    }

  public:
    Validator(Instance &instance) : instance(instance) {}

    void validate();
};

} // namespace Mitey
