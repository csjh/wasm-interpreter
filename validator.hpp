#include "interpreter.hpp"

namespace Mitey {

class Validator {
    Instance &instance;
    FunctionInfo current_fn;
    std::vector<std::vector<valtype>> control_stack;

    void validate(uint8_t *&iter, const Signature &signature,
                  bool is_func = false);

  public:
    Validator(Instance &instance) : instance(instance) {}

    void validate();
};

} // namespace Mitey
