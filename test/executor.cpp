#include "../interpreter.hpp"
#include "../validator.hpp"
#include "json.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <variant>
#include <vector>

struct value {
    std::string type;
    std::string value;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(value, type, value)

std::vector<mitey::WasmValue> to_wasm_values(const std::vector<value> &values) {
    std::vector<mitey::WasmValue> result;
    for (auto &v : values) {
        if (v.type == "i32") {
            result.push_back(
                mitey::WasmValue(static_cast<uint32_t>(std::stoul(v.value))));
        } else if (v.type == "i64") {
            result.push_back(mitey::WasmValue(std::stoull(v.value)));
        } else if (v.type == "f32") {
            if (v.value == "nan:canonical") {
                result.push_back(
                    mitey::WasmValue(std::numeric_limits<float>::quiet_NaN()));
            } else if (v.value == "nan:arithmetic") {
                result.push_back(mitey::WasmValue(
                    std::numeric_limits<float>::signaling_NaN()));
            } else {
                uint32_t bytes = std::stoul(v.value);
                result.push_back(
                    mitey::WasmValue(*reinterpret_cast<float *>(&bytes)));
            }
        } else if (v.type == "f64") {
            if (v.value == "nan:canonical") {
                result.push_back(
                    mitey::WasmValue(std::numeric_limits<double>::quiet_NaN()));
            } else if (v.value == "nan:arithmetic") {
                result.push_back(mitey::WasmValue(
                    std::numeric_limits<double>::signaling_NaN()));
            } else {
                uint64_t bytes = std::stoull(v.value);
                result.push_back(
                    mitey::WasmValue(*reinterpret_cast<double *>(&bytes)));
            }
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

struct get_action {
    std::string module;
    std::string field;
};

namespace nlohmann {
template <> struct adl_serializer<get_action> {
    static void to_json(json &j, const get_action &opt) {
        j = json{{"module", opt.module}, {"field", opt.field}};
    }

    static void from_json(const json &j, get_action &opt) {
        if (j.contains("module")) {
            opt.module = j["module"];
        } else {
            opt.module = "default";
        }
        opt.field = j["field"];
    }
};
} // namespace nlohmann

struct invoke_action {
    std::string module;
    std::string field;
    std::vector<value> args;
};

namespace nlohmann {
template <> struct adl_serializer<invoke_action> {
    static void to_json(json &j, const invoke_action &opt) {
        j = json{
            {"module", opt.module}, {"field", opt.field}, {"args", opt.args}};
    }

    static void from_json(const json &j, invoke_action &opt) {
        if (j.contains("module")) {
            opt.module = j["module"];
        } else {
            opt.module = "default";
        }
        opt.field = j["field"];
        opt.args = j["args"];
    }
};
} // namespace nlohmann

using action = std::variant<get_action, invoke_action>;

namespace nlohmann {
template <> struct adl_serializer<action> {
    static void to_json(json &j, const action &opt) {
        std::visit([&j](auto &&arg) { j = arg; }, opt);
    }

    static void from_json(const json &j, action &opt) {
        if (j["type"] == "get") {
            opt = j.get<get_action>();
        } else if (j["type"] == "invoke") {
            opt = j.get<invoke_action>();
        } else {
            std::cerr << "Unknown action type: " << j["type"] << std::endl;
        }
    }
};
} // namespace nlohmann

struct test_module {
    std::string type;
    int line;
    std::string name;
    std::string filename;
};

namespace nlohmann {
template <> struct adl_serializer<test_module> {
    static void to_json(json &j, const test_module &opt) {
        j = json{{"type", opt.type},
                 {"line", opt.line},
                 {"name", opt.name},
                 {"filename", opt.filename}};
    }

    static void from_json(const json &j, test_module &opt) {
        opt.type = j["type"];
        opt.line = j["line"];
        opt.filename = j["filename"];
        if (j.contains("name")) {
            opt.name = j["name"];
        } else {
            opt.name = "default";
        }
    }
};
} // namespace nlohmann

struct test_malformed {
    std::string type;
    int line;
    std::string filename;
    std::string text;
    std::string module_type;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(test_malformed, type, line, filename, text,
                                   module_type)

struct test_unlinkable {
    std::string type;
    int line;
    std::string filename;
    std::string text;
    std::string module_type;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(test_unlinkable, type, line, filename, text,
                                   module_type)

struct test_register {
    std::string type;
    int line;
    std::string name;
    std::string as;
};

namespace nlohmann {
template <> struct adl_serializer<test_register> {
    static void to_json(json &j, const test_register &opt) {
        j = json{{"type", opt.type},
                 {"line", opt.line},
                 {"as", opt.as},
                 {"name", opt.name}};
    }

    static void from_json(const json &j, test_register &opt) {
        opt.type = j["type"];
        opt.line = j["line"];
        if (j.contains("name")) {
            opt.name = j["name"];
        } else {
            opt.name = "default";
        }
        opt.as = j["as"];
    }
};
} // namespace nlohmann

struct test_return {
    std::string type;
    int line;
    action action;
    std::vector<value> expected;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(test_return, type, line, action, expected)

struct test_action {
    std::string type;
    int line;
    action action;
    std::vector<value> expected;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(test_action, type, line, action, expected)

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
    std::vector<only_type> expected;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(test_exhaustion, type, line, action, text,
                                   expected)

struct test_uninstantiable {
    std::string type;
    int line;
    std::string filename;
    std::string text;
    std::string module_type;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(test_uninstantiable, type, line, filename,
                                   text, module_type)

using Tests = std::variant<test_module, test_malformed, test_unlinkable,
                           test_return, test_action, test_invalid, test_trap,
                           test_exhaustion, test_register, test_uninstantiable>;

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
        } else if (j["type"] == "assert_unlinkable") {
            opt = j.get<test_unlinkable>();
        } else if (j["type"] == "assert_trap") {
            opt = j.get<test_trap>();
        } else if (j["type"] == "assert_exhaustion") {
            opt = j.get<test_exhaustion>();
        } else if (j["type"] == "action") {
            opt = j.get<test_action>();
        } else if (j["type"] == "register") {
            opt = j.get<test_register>();
        } else if (j["type"] == "assert_uninstantiable") {
            opt = j.get<test_uninstantiable>();
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

std::unique_ptr<mitey::Instance> from_file(const std::string &filename,
                                           const mitey::Imports &imports) {
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

    return std::make_unique<mitey::Instance>(std::move(bytes), length, imports);
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

    std::unordered_map<std::string, std::unique_ptr<mitey::Instance>> instances;
    mitey::Exports spectest{
        {"global_i32", std::make_shared<mitey::WasmGlobal>(
                           mitey::valtype::i32, mitey::mut::const_, 0)},
        {"global_i64", std::make_shared<mitey::WasmGlobal>(
                           mitey::valtype::i64, mitey::mut::const_, 0)},
        {"global_f32", std::make_shared<mitey::WasmGlobal>(
                           mitey::valtype::f32, mitey::mut::const_, 0)},
        {"global_f64", std::make_shared<mitey::WasmGlobal>(
                           mitey::valtype::f64, mitey::mut::const_, 0)},
        {"table",
         std::make_shared<mitey::WasmTable>(mitey::valtype::funcref, 10, 20)},
        {"memory", std::make_shared<mitey::WasmMemory>(1, 2)},
        {"print", mitey::FunctionInfo(
                      [&](mitey::WasmValue *) {
                          std::cout << "spectest print" << std::endl;
                      },
                      {{}, {}})},
        {"print_i32", mitey::FunctionInfo(
                          [&](mitey::WasmValue *args) {
                              std::cout << "spectest print_i32: " << args[0].i32
                                        << std::endl;
                          },
                          {{mitey::valtype::i32}, {}})},
        {"print_i64", mitey::FunctionInfo(
                          [&](mitey::WasmValue *args) {
                              std::cout << "spectest print_i64: " << args[0].i64
                                        << std::endl;
                          },
                          {{mitey::valtype::i64}, {}})},
        {"print_f32", mitey::FunctionInfo(
                          [&](mitey::WasmValue *args) {
                              std::cout << "spectest print_f32: " << args[0].f32
                                        << std::endl;
                          },
                          {{mitey::valtype::f32}, {}})},
        {"print_f64", mitey::FunctionInfo(
                          [&](mitey::WasmValue *args) {
                              std::cout << "spectest print_f64: " << args[0].f64
                                        << std::endl;
                          },
                          {{mitey::valtype::f64}, {}})},
        {"print_i32_f32",
         mitey::FunctionInfo(
             [&](mitey::WasmValue *args) {
                 std::cout << "spectest print_i32_f32: " << args[0].i32 << " "
                           << args[1].f32 << std::endl;
             },
             {{mitey::valtype::i32, mitey::valtype::f32}, {}})},
        {"print_f64_f64",
         mitey::FunctionInfo(
             [&](mitey::WasmValue *args) {
                 std::cout << "spectest print_f64_f64: " << args[0].f64 << " "
                           << args[1].f64 << std::endl;
             },
             {{mitey::valtype::f64, mitey::valtype::f64}, {}})}};

    mitey::Imports imports{{"spectest", spectest}};

    auto execute_action = [&](const action &a) {
        if (std::holds_alternative<get_action>(a)) {
            auto &action = std::get<get_action>(a);
            return std::vector{
                std::get<std::shared_ptr<mitey::WasmGlobal>>(
                    instances[action.module]->get_exports().at(action.field))
                    ->value};
        } else if (std::holds_alternative<invoke_action>(a)) {
            auto &action = std::get<invoke_action>(a);
            return std::get<mitey::FunctionInfo>(
                       instances[action.module]->get_exports().at(action.field))
                .to()(to_wasm_values(action.args));
        } else {
            throw std::runtime_error("Unknown action type");
        }
    };

    for (auto &t : wast.commands) {
        nlohmann::json j = t;
        std::cerr << "Running test: " << j << std::endl;

        if (std::holds_alternative<test_module>(t)) {
            auto &m = std::get<test_module>(t);
            instances[m.name] =
                from_file(resolve_relative(filename, m.filename), imports);
            instances["default"] =
                from_file(resolve_relative(filename, m.filename), imports);
        } else if (std::holds_alternative<test_malformed>(t)) {
            auto &m = std::get<test_malformed>(t);
            if (m.filename.ends_with(".wat"))
                continue;
            try {
                from_file(resolve_relative(filename, m.filename), imports);

                std::cerr << "Expected malformed error for file: " << m.filename
                          << std::endl;
                return 1;
            } catch (mitey::malformed_error &e) {
                if (std::string(e.what()) != m.text) {
                    std::cerr << "Expected error message: " << m.text
                              << " but got: " << e.what() << std::endl;
                    return 1;
                }
            } catch (std::runtime_error &e) {
                std::cerr << "Expected malformed error with message: " << m.text
                          << " but got: " << e.what() << std::endl;
                return 1;
            }
        } else if (std::holds_alternative<test_return>(t)) {
            auto &m = std::get<test_return>(t);

            std::vector<mitey::WasmValue> result = execute_action(m.action);

            if (result.size() != m.expected.size()) {
                std::cerr << "Expected " << m.expected.size()
                          << " results but got " << result.size() << std::endl;
                return 1;
            }

            auto expected_results = to_wasm_values(m.expected);

            auto test = [](std::string &ty, mitey::WasmValue &res,
                           mitey::WasmValue &exp) {
                if (ty == "i32" && res.i32 != exp.i32) {
                    std::cerr << "Expected: " << exp.i32
                              << " but got: " << res.i32 << std::endl;
                    return false;
                } else if (ty == "i64" && res.i64 != exp.i64) {
                    std::cerr << "Expected: " << exp.i64
                              << " but got: " << res.i64 << std::endl;
                    return false;
                } else if (ty == "f32" && (res.f32 != exp.f32) &&
                           (std::isnan(res.f32) != std::isnan(exp.f32))) {
                    std::cerr << "Expected: " << exp.f32
                              << "(isnan: " << std::isnan(exp.f32) << ")"
                              << " but got: " << res.f32
                              << "(isnan: " << std::isnan(res.f32) << ")"
                              << std::endl;
                    return false;
                } else if (ty == "f64" && (res.f64 != exp.f64) &&
                           (std::isnan(res.f64) != std::isnan(exp.f64))) {
                    std::cerr << "Expected: " << exp.f64
                              << "(isnan: " << std::isnan(exp.f64) << ")"
                              << " but got: " << res.f64
                              << "(isnan: " << std::isnan(res.f64) << ")"
                              << std::endl;
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
                from_file(resolve_relative(filename, m.filename), imports);

                std::cerr << "Expected validation error for file: "
                          << m.filename << std::endl;
                return 1;
            } catch (mitey::validation_error &e) {
                if (std::string(e.what()) != m.text) {
                    std::cerr << "Expected error message: " << m.text
                              << " but got: " << e.what() << std::endl;
                    return 1;
                }
            } catch (std::runtime_error &e) {
                std::cerr << "Expected validation error with message: "
                          << m.text << " but got: " << e.what() << std::endl;
                return 1;
            }
        } else if (std::holds_alternative<test_trap>(t)) {
            auto &m = std::get<test_trap>(t);
            try {
                execute_action(m.action);
                std::cerr << "Expected trap for test" << std::endl;
                return 1;
            } catch (mitey::trap_error &e) {
                if (std::string(e.what()) != m.text) {
                    std::cerr << "Expected trap: " << m.text
                              << " but got: " << e.what() << std::endl;
                    return 1;
                }
            } catch (std::runtime_error &e) {
                std::cerr << "Expected trap for action: " << m.text
                          << " but got: " << e.what() << std::endl;
                return 1;
            }
        } else if (std::holds_alternative<test_exhaustion>(t)) {
            auto &m = std::get<test_exhaustion>(t);
            try {
                execute_action(m.action);

                std::cerr << "Expected exhaustion for test" << std::endl;
                return 1;
            } catch (mitey::trap_error &e) {
                if (std::string(e.what()) != m.text) {
                    std::cerr << "Expected message: " << m.text
                              << " but got: " << e.what() << std::endl;
                    return 1;
                }
            } catch (std::runtime_error &e) {
                std::cerr << "Expected exhaustion error: " << m.text
                          << " but got: " << e.what() << std::endl;
                return 1;
            }
        } else if (std::holds_alternative<test_action>(t)) {
            auto &m = std::get<test_action>(t);
            assert(m.expected.size() == 0);
            execute_action(m.action);
        } else if (std::holds_alternative<test_unlinkable>(t)) {
            auto &m = std::get<test_unlinkable>(t);
            try {
                from_file(resolve_relative(filename, m.filename), imports);

                std::cerr << "Expected link error for file: " << m.filename
                          << std::endl;
                return 1;
            } catch (mitey::link_error &e) {
                if (std::string(e.what()) != m.text) {
                    std::cerr << "Expected error message: " << m.text
                              << " but got: " << e.what() << std::endl;
                    return 1;
                }
            } catch (std::runtime_error &e) {
                std::cerr << "Expected link error with message: " << m.text
                          << " but got: " << e.what() << std::endl;
                return 1;
            }
        } else if (std::holds_alternative<test_uninstantiable>(t)) {
            auto &m = std::get<test_uninstantiable>(t);
            try {
                from_file(resolve_relative(filename, m.filename), imports);

                std::cerr << "Expected uninstantiable error for file: "
                          << m.filename << std::endl;
                return 1;
            } catch (mitey::uninstantiable_error &e) {
                if (std::string(e.what()) != m.text) {
                    std::cerr << "Expected error message: " << m.text
                              << " but got: " << e.what() << std::endl;
                    return 1;
                }
            } catch (std::runtime_error &e) {
                std::cerr << "Expected uninstantiable error with message: "
                          << m.text << " but got: " << e.what() << std::endl;
                return 1;
            }
        } else if (std::holds_alternative<test_register>(t)) {
            auto &m = std::get<test_register>(t);
            imports[m.as] = instances[m.name]->get_exports();
        } else {
            std::cerr << "Unhandled std::variant type" << std::endl;
        }
    }

    return 0;
}
