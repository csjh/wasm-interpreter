#include "module.hpp"
#include <memory>

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

    auto module = mitey::Module::compile(std::move(bytes), length);
    auto instance = module->instantiate();
}
