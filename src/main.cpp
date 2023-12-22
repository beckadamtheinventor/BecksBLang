
#include "BecksBLang.hpp"
std::string ERROR_STRINGS[BecksBLang::NUM_ERRORS] = {
    "",
    "No file data or file not found",
    "Invalid file data",
    "Divide by Zero",
    "Out of bounds read",
    "Out of bounds write",
    "Out of bounds variable",
    "Out of bounds data index",
    "Out of bounds const data",
    "Stack underflow",
    "Stack overflow",
    "Stack out of bounds",
    "Invalid opcode",
    "Invalid argument",
    "Invalid string",
    "Bad return",
    "Bad jump",
    "Execution reached end of file",
};

int main(int argc, char **argv) {
    if (argc >= 2) {
        BecksBLang::BytecodeFile file(argv[1]);
        int err;
        if ((err = file.run())) {
            if (err != BecksBLang::DONE) {
                printf("\nAn error occurred during execution.\n");
                if (err < BecksBLang::NUM_ERRORS) {
                    printf("Error %u: %s.\n", err, ERROR_STRINGS[err].c_str());
                }
            }
        }
    } else {
        printf("Usage: %s program.bin\n", argv[0]);
    }
    return 0;
}