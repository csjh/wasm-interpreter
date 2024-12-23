#include "instance.hpp"
#include "module.hpp"
#include <chrono>
#include <memory>

uint64_t clock_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

int main(int argv, char **argc) {
    if (argv < 2) {
        printf("Usage: %s <filename>\n", argc[0]);
        return 1;
    }

    char *filename = argc[1];

    FILE *file = fopen(filename, "rb");
    if (!file) {
        printf("Could not open file %s\n", filename);
        return 1;
    }

    fseek(file, 0, SEEK_END);
    long length = ftell(file);
    fseek(file, 0, SEEK_SET);

    auto bytes = std::make_unique<uint8_t[]>(length);
    fread(bytes.get(), 1, length, file);
    fclose(file);

    auto start = std::chrono::high_resolution_clock::now();
    auto module = mitey::Module::compile(std::move(bytes), length);
    auto end = std::chrono::high_resolution_clock::now();
    printf("Compilation/validation took %fms\n",
           std::chrono::duration<float, std::milli>(end - start).count());

    mitey::FunctionInfo clock_fn({{}, {mitey::valtype::i64}},
                                 mitey::wasm_functionify<clock_ms>);
    mitey::Imports imports{{"env", {{"clock_ms", clock_fn}}}};
    auto instance = module->instantiate(imports);

    float score =
        std::get<mitey::FunctionInfo>(instance->get_exports().at("run"))
            .to<float()>()();

    printf("Score: %f\n", score);
}
