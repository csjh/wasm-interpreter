#include "interpreter.hpp"

namespace mitey {
class Validator {
    Instance &instance;
    uint32_t n_data;
    FunctionInfo current_fn;
    std::vector<std::vector<valtype>> control_stack;

    void validate(uint8_t *&iter, const Signature &signature,
                  bool is_func = false);

  public:
    Validator(Instance &instance, uint32_t n_data)
        : instance(instance), n_data(n_data) {}

    void validate();
};

} // namespace mitey
