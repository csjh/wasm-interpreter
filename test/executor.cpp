#include "json.hpp"
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

struct value {
    std::string type;
    std::string value;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(value, type, value)

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
    static void to_json(json &j, const Tests &opt) { /* not implemented */
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

    std::cout << "source_filename: " << wast.source_filename << std::endl;
    for (auto &t : wast.commands) {
        if (std::holds_alternative<test_module>(t)) {
            auto &m = std::get<test_module>(t);
            std::cout << "type: " << m.type << std::endl;
            std::cout << "line: " << m.line << std::endl;
            std::cout << "filename: " << m.filename << std::endl;
        } else if (std::holds_alternative<test_malformed>(t)) {
            auto &m = std::get<test_malformed>(t);
            std::cout << "type: " << m.type << std::endl;
            std::cout << "line: " << m.line << std::endl;
            std::cout << "filename: " << m.filename << std::endl;
            std::cout << "text: " << m.text << std::endl;
            std::cout << "module_type: " << m.module_type << std::endl;
        } else if (std::holds_alternative<test_return>(t)) {
            auto &m = std::get<test_return>(t);
            std::cout << "type: " << m.type << std::endl;
            std::cout << "line: " << m.line << std::endl;
            std::cout << "action.type: " << m.action.type << std::endl;
            std::cout << "action.field: " << m.action.field << std::endl;
            for (auto &a : m.action.args) {
                std::cout << "args.type: " << a.type << std::endl;
                std::cout << "args.value: " << a.value << std::endl;
            }
            for (auto &a : m.expected) {
                std::cout << "expected.type: " << a.type << std::endl;
                std::cout << "expected.value: " << a.value << std::endl;
            }
        } else if (std::holds_alternative<test_invalid>(t)) {
            auto &m = std::get<test_invalid>(t);
            std::cout << "type: " << m.type << std::endl;
            std::cout << "line: " << m.line << std::endl;
            std::cout << "filename: " << m.filename << std::endl;
            std::cout << "text: " << m.text << std::endl;
            std::cout << "module_type: " << m.module_type << std::endl;
        } else if (std::holds_alternative<test_trap>(t)) {
            auto &m = std::get<test_trap>(t);
            std::cout << "type: " << m.type << std::endl;
            std::cout << "line: " << m.line << std::endl;
            std::cout << "action.type: " << m.action.type << std::endl;
            std::cout << "action.field: " << m.action.field << std::endl;
            for (auto &a : m.action.args) {
                std::cout << "args.type: " << a.type << std::endl;
                std::cout << "args.value: " << a.value << std::endl;
            }
            for (auto &a : m.expected) {
                std::cout << "expected.type: " << a.type << std::endl;
            }
        } else if (std::holds_alternative<test_exhaustion>(t)) {
            auto &m = std::get<test_exhaustion>(t);
            std::cout << "type: " << m.type << std::endl;
            std::cout << "line: " << m.line << std::endl;
            std::cout << "action.type: " << m.action.type << std::endl;
            std::cout << "action.field: " << m.action.field << std::endl;
            for (auto &a : m.action.args) {
                std::cout << "args.type: " << a.type << std::endl;
                std::cout << "args.value: " << a.value << std::endl;
            }
            for (auto &a : m.expected) {
                std::cout << "expected.type: " << a.type << std::endl;
                std::cout << "expected.value: " << a.value << std::endl;
            }
        }
    }
}
