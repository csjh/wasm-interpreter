#include "interpreter.hpp"

namespace Mitey {

class Validator {
    Instance &instance;
    FunctionInfo current_fn;
    std::vector<std::vector<valtype>> control_stack;

    void validate(uint8_t *&iter, const Signature &signature,
                  bool is_func = false);

    Signature read_blocktype(uint8_t *&iter) {
        uint8_t byte = *iter;
        if (byte == static_cast<uint8_t>(valtype::empty)) {
            ++iter;
            return {{}, {}};
        } else if (is_valtype(byte)) {
            ++iter;
            return {{}, {static_cast<valtype>(byte)}};
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
