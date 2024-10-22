#include "../interpreter.hpp"
#include "../validator.hpp"
#include "json.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <system_error>
#include <variant>
#include <vector>

struct value {
    std::string type;
    std::string value;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(value, type, value)

std::vector<Mitey::WasmValue> to_wasm_values(const std::vector<value> &values) {
    std::vector<Mitey::WasmValue> result;
    for (auto &v : values) {
        if (v.type == "i32") {
            result.push_back(
                Mitey::WasmValue(static_cast<uint32_t>(std::stoul(v.value))));
        } else if (v.type == "i64") {
            result.push_back(Mitey::WasmValue(std::stoull(v.value)));
        } else if (v.type == "f32") {
            result.push_back(Mitey::WasmValue(std::stof(v.value)));
        } else if (v.type == "f64") {
            result.push_back(Mitey::WasmValue(std::stod(v.value)));
        } else {
            std::cerr << "Unknown type: " << v.type << std::endl;
        }
    }
    return result;
}

struct only_type {
    std::string type;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(only_type, type)

struct action {
    std::string type;
    std::string field;
    std::vector<value> args;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(action, type, field, args)

struct test_module {
    std::string type;
    int line;
    std::string filename;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(test_module, type, line, filename)

struct test_malformed {
    std::string type;
    int line;
    std::string filename;
    std::string text;
    std::string module_type;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(test_malformed, type, line, filename, text,
                                   module_type)

struct test_return {
    std::string type;
    int line;
    action action;
    std::vector<value> expected;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(test_return, type, line, action, expected)

struct test_invalid {
    std::string type;
    int line;
    std::string filename;
    std::string text;
    std::string module_type;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(test_invalid, type, line, filename, text,
                                   module_type)

struct test_trap {
    std::string type;
    int line;
    action action;
    std::string text;
    std::vector<only_type> expected;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(test_trap, type, line, action, text,
                                   expected)

struct test_exhaustion {
    std::string type;
    int line;
    action action;
    std::string text;
    std::vector<value> expected;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(test_exhaustion, type, line, action, text,
                                   expected)

using Tests = std::variant<test_module, test_malformed, test_return,
                           test_invalid, test_trap, test_exhaustion>;

namespace nlohmann {
template <> struct adl_serializer<Tests> {
    static void to_json(json &j, const Tests &opt) {
        std::visit([&j](auto &&arg) { j = arg; }, opt);
    }

    static void from_json(const json &j, Tests &opt) {
        if (j["type"] == "module") {
            opt = j.get<test_module>();
        } else if (j["type"] == "assert_return") {
            opt = j.get<test_return>();
        } else if (j["type"] == "assert_malformed") {
            opt = j.get<test_malformed>();
        } else if (j["type"] == "assert_invalid") {
            opt = j.get<test_invalid>();
        } else if (j["type"] == "assert_trap") {
            opt = j.get<test_trap>();
        } else if (j["type"] == "assert_exhaustion") {
            opt = j.get<test_exhaustion>();
        } else {
            std::cerr << "Unknown type: " << j["type"] << std::endl;
        }
    }
};
} // namespace nlohmann

struct wastjson {
    std::string source_filename;
    std::vector<Tests> commands;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(wastjson, source_filename, commands)

Mitey::Instance from_file(const std::string &filename) {
    std::ifstream wasm_file{filename, std::ios::binary};
    if (!wasm_file) {
        throw std::system_error(errno, std::system_category(), filename);
    }

    wasm_file.seekg(0, std::ios::end);
    long length = wasm_file.tellg();
    wasm_file.seekg(0, std::ios::beg);

    // load data into a unique_ptr
    std::unique_ptr<uint8_t, void (*)(uint8_t *)> bytes(
        new uint8_t[length], [](uint8_t *ptr) { delete[] ptr; });

    wasm_file.read(reinterpret_cast<char *>(bytes.get()), length);
    wasm_file.close();

    return Mitey::Instance(std::move(bytes), length);
}

namespace fs = std::filesystem;
fs::path resolve_relative(const fs::path &file1, const fs::path &file2) {
    return fs::absolute(file1.parent_path() / file2).lexically_normal();
}

int main(int argv, char **argc) {
    if (argv != 2) {
        std::cerr << "Usage: " << argc[0] << " <filename>" << std::endl;
        return 1;
    }

    // takes a json file as input
    std::string filename = argc[1];

    // read the json file
    std::ifstream ifs{filename};
    nlohmann::json j;
    ifs >> j;

    auto wast = j.template get<wastjson>();

    std::cout << "Testing file: " << wast.source_filename << std::endl;
    if (!std::holds_alternative<test_module>(wast.commands[0])) {
        std::cerr << "First command is not a module" << std::endl;
        return 1;
    }
    test_module &m = std::get<test_module>(wast.commands[0]);
    Mitey::Instance instance =
        from_file(resolve_relative(filename, m.filename));
    wast.commands.erase(wast.commands.begin());

    for (auto &t : wast.commands) {
        nlohmann::json j = t;
        std::cerr << "Running test: " << j << std::endl;

        if (std::holds_alternative<test_module>(t)) {
            std::cerr << "Duplicate module found" << std::endl;
            return 1;
        } else if (std::holds_alternative<test_malformed>(t)) {
            // auto &m = std::get<test_malformed>(t);
            // malformation is only for wat
            continue;
        } else if (std::holds_alternative<test_return>(t)) {
            auto &m = std::get<test_return>(t);

            auto result =
                instance.execute(m.action.field, to_wasm_values(m.action.args));

            if (result.size() != m.expected.size()) {
                std::cerr << "Expected " << m.expected.size()
                          << " results but got " << result.size() << std::endl;
            }

            auto expected_results = to_wasm_values(m.expected);

            auto test = [](std::string &ty, Mitey::WasmValue &res,
                           Mitey::WasmValue &exp) {
                if (ty == "i32" && res.i32 != exp.i32) {
                    std::cerr << "Expected: " << exp.i32
                              << " but got: " << res.i32 << std::endl;
                    return false;
                } else if (ty == "i64" && res.i64 != exp.i64) {
                    std::cerr << "Expected: " << exp.i64
                              << " but got: " << res.i64 << std::endl;
                    return false;
                } else if (ty == "f32" && res.f32 != exp.f32) {
                    std::cerr << "Expected: " << exp.f32
                              << " but got: " << res.f32 << std::endl;
                    return false;
                } else if (ty == "f64" && res.f64 != exp.f64) {
                    std::cerr << "Expected: " << exp.f64
                              << " but got: " << res.f64 << std::endl;
                    return false;
                }
                return true;
            };

            for (uint32_t i = 0; i < result.size(); ++i) {
                if (!test(m.expected[i].type, result[i], expected_results[i])) {
                    return 1;
                }
            }
        } else if (std::holds_alternative<test_invalid>(t)) {
            auto &m = std::get<test_invalid>(t);
            try {
                Mitey::Instance invalid_instance =
                    from_file(resolve_relative(filename, m.filename));

                std::cerr << "Expected validation error for file: "
                          << m.filename << std::endl;
            } catch (Mitey::validation_error &e) {
            }
        } else if (std::holds_alternative<test_trap>(t)) {
            auto &m = std::get<test_trap>(t);
            try {
                auto result = instance.execute(m.action.field,
                                               to_wasm_values(m.action.args));

                std::cerr << "Expected trap for action: " << m.action.field
                          << std::endl;
            } catch (Mitey::trap_error &e) {
                if (e.what() != m.text) {
                    std::cerr << "Expected: " << m.text
                              << " but got: " << e.what() << std::endl;
                }
            }
        } else if (std::holds_alternative<test_exhaustion>(t)) {
            // auto &m = std::get<test_exhaustion>(t);
            // todo: see if there's some memory trick to trap efficiently
        }
    }
}
