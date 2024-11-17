#include "module.hpp"
#include <memory>

void free_u8(uint8_t *ptr) { free(ptr); }

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

    uint8_t *bytes = (uint8_t *)malloc(length);
    fread(bytes, 1, length, file);
    fclose(file);

    mitey::Instance instance(
        std::unique_ptr<uint8_t, void (*)(uint8_t *)>(bytes, free_u8), length);
}
