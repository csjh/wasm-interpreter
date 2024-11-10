#include "instance.hpp"

namespace mitey {
class Validator {
    Instance &instance;
    FunctionInfo current_fn;
    std::vector<std::vector<valtype>> control_stack;

    void validate(safe_byte_iterator &iter, const Signature &signature,
                  bool is_func = false);

  public:
    Validator(Instance &instance) : instance(instance) {}

    void validate(uint8_t *end);
};

} // namespace mitey
