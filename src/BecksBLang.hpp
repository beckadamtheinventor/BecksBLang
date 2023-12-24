#ifndef __BecksBLang_hpp__
#define __BecksBLang_hpp__

#include <algorithm>
#include <cstring>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
namespace BecksBLang {
    typedef unsigned int uint;
    typedef unsigned short ushort;
    typedef unsigned char uchar;

    enum ERR {
        SUCCESS = 0,
        NO_FILE_DATA,
        INVALID_FILE_DATA,
        DIVIDE_BY_ZERO,
        OUT_OF_BOUNDS_READ,
        OUT_OF_BOUNDS_WRITE,
        OUT_OF_BOUNDS_VARIABLE,
        OUT_OF_BOUNDS_DATA_INDEX,
        OUT_OF_BOUNDS_CONST_DATA,
        STACK_UNDERFLOW,
        STACK_OVERFLOW,
        STACK_OUT_OF_BOUNDS,
        INVALID_OPCODE,
        INVALID_ARGUMENT,
        INVALID_STRING,
        BAD_RETURN,
        BAD_JUMP,
        EXEC_END_OF_FILE,
        NUM_ERRORS,
        DONE = -1,
    };
    enum OPC {
        NOP = 0,
        END,
        STORE_VAR,
        LOAD_VAR,
        LOAD_IMM,
        AND_VAR,
        OR_VAR,
        XOR_VAR,
        NOT,
        ITOF,
        FTOI,
        ADD_VAR,
        SUB_VAR,
        MUL_VAR,
        DIV_VAR,
        MOD_VAR,
        NEG,
        SIGN,
        ABS,
        FADD_VAR,
        FSUB_VAR,
        FMUL_VAR,
        FDIV_VAR,
        FMOD_VAR,
        FNEG,
        FSIGN,
        FABS,
        FPOW_VAR,
        PRINT_NEWLINE,
        PRINT_STR,
        PRINT_INT,
        PRINT_UINT,
        PRINT_FLOAT,
        PUSH,
        POP,
        CALL,
        RETURN,
        JUMP,
        JREL,
        BZERO,
        BNZERO,
        BPOS,
        BNEG,
    };
    
    // class containing Execution Context such as registers and variables. 4624 bytes each.
    class ExecutionContext {
        public:
        static const uint num_vars = 1024;
        static const uint stack_depth = 128;
        int err;
        uint pc = 0;
        uint sp = stack_depth;
        uint bp = 0;
        uint stack[stack_depth];
        union {
            uint ans;
            float ansf;
        };
        union {
            uint varsi[num_vars];
            float varsf[num_vars];
        };

        ExecutionContext() {
            err = bp = sp = pc = ans = 0;
            memset(&varsi, 0, num_vars*sizeof(uint));
            memset(&stack, 0, stack_depth*sizeof(uint));
        }

        void set_var(ushort varno, uint val) {
            if (varno < num_vars) {
                varsi[varno] = val;
            } else {
                err = ERR::OUT_OF_BOUNDS_VARIABLE;
            }
        }

        void set_var(ushort varno, float val) {
            if (varno < num_vars) {
                varsf[varno] = val;
            } else {
                err = ERR::OUT_OF_BOUNDS_VARIABLE;
            }
        }

        template<class T>
        T get_var(ushort varno) {
            if (varno < num_vars) {
                return *(T*)(&varsi[varno]);
            } else {
                err = ERR::OUT_OF_BOUNDS_VARIABLE;
            }
            return 0;
        }

        // push uint to the stack.
        // errors with STACK_OVERFLOW if sp ends up out of bounds.
        void push(uint val) {
            if (sp == 0 || sp > stack_depth) {
                err = ERR::STACK_OVERFLOW;
            } else {
                stack[--sp] = val;
            }
        }

        // pop uint from the stack.
        // errors with STACK_UNDERFLOW if SP ends up out of bounds.
        // errors with STACK_OUT_OF_BOUNDS if the pop happens with SP >= BP (stack pointer underflows function base)
        uint pop(void) {
            if (sp >= bp) {

            } else if (sp >= stack_depth) {
                err = ERR::STACK_UNDERFLOW;
            } else {
                return stack[sp++];
            }
            return 0;
        }

    };

    class Bytecode {
        constexpr static const size_t MAX_BYTECODE_LENGTH = 1 << 24;
        constexpr static const size_t MAX_CONST_DATA_ENTRIES = 1 << 16;

        ExecutionContext ec;
        size_t length = 0;
        size_t clength = 0;
        uchar *data = nullptr;
        uchar *cdata = nullptr;
        size_t cdatanumentries = 0;
        uint cdataentries[MAX_CONST_DATA_ENTRIES];
        public:
        Bytecode() : Bytecode(nullptr, 0, nullptr, 0) {};
        Bytecode(uchar *data, size_t length, uchar *cdata, size_t clength) {
            this->data = data;
            this->length = length;
            this->cdata = cdata;
            this->clength = clength;
            ec = ExecutionContext();
            memset(&cdataentries, 0, MAX_CONST_DATA_ENTRIES*sizeof(uint));
            cdatanumentries = 0;
            if (cdata != nullptr && clength > 0) {
                size_t p = 0;
                for (; cdatanumentries < MAX_CONST_DATA_ENTRIES; cdatanumentries++) {
                    ushort l = *(ushort*)(&cdata[p]);
                    if (l == 0 || p+l+2 == clength) {
                        break;
                    }
                    if (p+l+2 > clength) {
                        ec.err = ERR::OUT_OF_BOUNDS_CONST_DATA;
                        break;
                    }
                    cdataentries[cdatanumentries] = p;
                    p += l + 2;
                }
            }
            if (this->data == nullptr || this->length == 0 || this->length >= MAX_BYTECODE_LENGTH) {
                ec.err = INVALID_FILE_DATA;
            }
        }

        // read data from a given offset of program data.
        template<class T>
        T read(uint addr) {
            T val = 0;
            if (addr + sizeof(T) <= std::min(length, MAX_BYTECODE_LENGTH)) {
                val = *(T*)(&data[addr]);
            } else {
                ec.err = ERR::OUT_OF_BOUNDS_READ;
            }
            return val;
        }

        /*
        // write data to a given offset of program data.
        // probably not gonna use this.
        template<class T>
        void write(uint addr, T val) {
            if (addr + sizeof(T) < std::min(this->length, MAX_BYTECODE_LENGTH)) {
                *(T*)(&data[addr]) = val;
            } else {
                ec.err = ERR::OUT_OF_BOUNDS_WRITE;
            }
        }
        */

        // return pointer to data prefixed with length as an unsigned short
        uchar *get_data(ushort datano) {
            if (datano < cdatanumentries) {
                return &cdata[cdataentries[datano]];
            } else {
                ec.err = ERR::OUT_OF_BOUNDS_DATA_INDEX;
            }
            return nullptr;
        }

        // returns true if null terminated string contains only characters 0x20-0x7D, and the length of the string is correct.
        bool str_is_valid(char *str, size_t len) {
            size_t i;
            for (i = 0; str[i]!=0; i++) {
                if ((unsigned)str[i] < 0x20 || (unsigned)str[i] >= 0x7E) {
                    return false;
                }
            }
            return (i+1 == len);
        }

        int execute() {
            do {
                char *str = nullptr;
                float argf = 0;
                uint arg = 0;
                if (ec.pc >= length) {
                    ec.err = ERR::EXEC_END_OF_FILE;
                    break;
                }
                uchar opcode = read<uchar>(ec.pc++);
                switch (opcode) {
                    case OPC::NOP:
                        break;
                    case OPC::END:
                        ec.err = ERR::DONE;
                        break;
                    case OPC::STORE_VAR:
                        arg = read<ushort>(ec.pc);
                        ec.pc += sizeof(ushort);
                        ec.set_var(arg, ec.ans);
                        break;
                    case OPC::LOAD_VAR:
                        arg = read<ushort>(ec.pc);
                        ec.pc += sizeof(ushort);
                        ec.ans = ec.get_var<uint>(arg);
                        break;
                    case OPC::LOAD_IMM:
                        ec.ans = read<uint>(ec.pc);
                        ec.pc += sizeof(uint);
                        break;
                    case OPC::ADD_VAR:
                        arg = read<ushort>(ec.pc);
                        ec.pc += sizeof(ushort);
                        ec.ans += ec.get_var<uint>(arg);
                        break;
                    case OPC::SUB_VAR:
                        arg = read<ushort>(ec.pc);
                        ec.pc += sizeof(ushort);
                        ec.ans -= ec.get_var<uint>(arg);
                        break;
                    case OPC::MUL_VAR:
                        arg = read<ushort>(ec.pc);
                        ec.pc += sizeof(ushort);
                        ec.ans *= ec.get_var<uint>(arg);
                        break;
                    case OPC::DIV_VAR:
                        arg = read<ushort>(ec.pc);
                        ec.pc += sizeof(ushort);
                        arg = ec.get_var<uint>(arg);
                        if (arg == 0) {
                            ec.err = ERR::DIVIDE_BY_ZERO;
                        } else {
                            ec.ans /= arg;
                        }
                        break;
                    case OPC::MOD_VAR:
                        arg = read<ushort>(ec.pc);
                        ec.pc += sizeof(ushort);
                        arg = ec.get_var<uint>(arg);
                        if (arg == 0) {
                            ec.err = ERR::DIVIDE_BY_ZERO;
                        } else {
                            ec.ans %= arg;
                        }
                        break;
                    case OPC::AND_VAR:
                        arg = read<ushort>(ec.pc);
                        ec.pc += sizeof(ushort);
                        ec.ans &= ec.get_var<uint>(arg);
                        break;
                    case OPC::OR_VAR:
                        arg = read<ushort>(ec.pc);
                        ec.pc += sizeof(ushort);
                        ec.ans |= ec.get_var<uint>(arg);
                        break;
                    case OPC::XOR_VAR:
                        arg = read<ushort>(ec.pc);
                        ec.pc += sizeof(ushort);
                        ec.ans ^= ec.get_var<uint>(arg);
                        break;
                    case OPC::NOT:
                        ec.ans = ~ec.ans;
                        break;
                    case OPC::NEG:
                        ec.ans = -ec.ans;
                        break;
                    case OPC::SIGN:
                        ec.ans = (ec.ans == 0 ? 0 : (ec.ans > 0 ? 1 : -1));
                        break;
                    case OPC::ITOF:
                        ec.ansf = ec.ans;
                        break;
                    case OPC::FTOI:
                        ec.ans = ec.ansf;
                        break;
                    case OPC::ABS:
                        if (ec.ans >> 31) {
                            ec.ans = -ec.ans;
                        };
                        break;
                    case OPC::FADD_VAR:
                        arg = read<ushort>(ec.pc);
                        ec.pc += sizeof(ushort);
                        ec.ansf += ec.get_var<float>(arg);
                        break;
                    case OPC::FSUB_VAR:
                        arg = read<ushort>(ec.pc);
                        ec.pc += sizeof(ushort);
                        ec.ansf += ec.get_var<float>(arg);
                        break;
                    case OPC::FMUL_VAR:
                        arg = read<ushort>(ec.pc);
                        ec.pc += sizeof(ushort);
                        ec.ansf *= ec.get_var<float>(arg);
                        break;
                    case OPC::FDIV_VAR:
                        arg = read<ushort>(ec.pc);
                        ec.pc += sizeof(ushort);
                        argf = ec.get_var<float>(arg);
                        if (argf == 0) {
                            ec.err = ERR::DIVIDE_BY_ZERO;
                        } else {
                            ec.ansf /= argf;
                        }
                        break;
                    case OPC::FMOD_VAR:
                        arg = read<ushort>(ec.pc);
                        ec.pc += sizeof(ushort);
                        argf = ec.get_var<float>(arg);
                        if (argf == 0) {
                            ec.err = ERR::DIVIDE_BY_ZERO;
                        } else {
                            ec.ansf = fmodf(ec.ansf, argf);
                        }
                        break;
                    case OPC::FNEG:
                        ec.ansf = -ec.ansf;
                        break;
                    case OPC::FABS:
                        arg = read<ushort>(ec.pc);
                        ec.pc += sizeof(ushort);
                        ec.set_var(arg, fabsf(ec.get_var<float>(arg)));
                        break;
                    case OPC::FSIGN:
                        ec.ansf = (ec.ansf == 0 ? 0 : (ec.ansf > 0 ? 1 : -1));
                        break;
                    case OPC::FPOW_VAR:
                        arg = read<ushort>(ec.pc);
                        ec.pc += sizeof(ushort);
                        argf = ec.get_var<float>(arg);
                        ec.ansf = powf(ec.ansf, argf);
                        break;
                    case OPC::PRINT_NEWLINE:
                        printf("\n");
                        break;
                    case OPC::PRINT_STR:
                        arg = read<ushort>(ec.pc);
                        ec.pc += 2;
                        str = (char*)get_data(arg);
                        // grab size word
                        arg = *(ushort*)str;
                        // bypass size word
                        str = &str[2];
                        // validate the string
                        if (str_is_valid(str, arg)) {
                            printf("%s", str);
                        } else {
                            ec.err = ERR::INVALID_STRING;
                        }
                        break;
                    case OPC::PRINT_INT:
                        printf("%d", ec.ans);
                        break;
                    case OPC::PRINT_UINT:
                        printf("%u", ec.ans);
                        break;
                    case OPC::PRINT_FLOAT:
                        printf("%f", ec.ansf);
                        break;
                    case OPC::PUSH:
                        ec.push(ec.ans);
                        break;
                    case OPC::POP:
                        ec.ans = ec.pop();
                        break;
                    case OPC::CALL:
                        arg = read<uint>(ec.pc);
                        ec.pc += sizeof(uint);
                        // save base pointer
                        ec.push(ec.bp);
                        // save return address
                        ec.push(ec.pc);
                        // save stack pointer -> base pointer
                        ec.bp = ec.sp;
                        // jump
                        ec.pc = arg;
                        // verify jump location is within the program
                        if (ec.pc >= length) {
                            ec.err = ERR::BAD_JUMP;
                        }
                        break;
                    case OPC::RETURN:
                        // check if the stack is in the correct spot (prevent jumping to values pushed within the function)
                        if (ec.sp != ec.bp) {
                            ec.err = ERR::BAD_RETURN;
                        } else {
                            ec.pc = ec.pop();
                            ec.bp = ec.pop();
                        }
                        break;
                    case OPC::JUMP:
                        ec.pc = read<uint>(ec.pc);
                        // verify jump location is within the program
                        if (ec.pc >= length) {
                            ec.err = ERR::BAD_JUMP;
                        }
                        break;
                    case OPC::JREL:
                        arg = read<ushort>(ec.pc);
                        ec.pc += 2 + (signed)arg;
                        // verify jump location is within the program
                        if (ec.pc >= length) {
                            ec.err = ERR::BAD_JUMP;
                        }
                        break;
                    case OPC::BZERO:
                        arg = read<ushort>(ec.pc);
                        ec.pc += 2;
                        if (ec.ans == 0) {
                            ec.pc += (signed)arg;
                            if (ec.pc >= length) {
                                ec.err = ERR::BAD_JUMP;
                            }
                        }
                        break;
                    case OPC::BNZERO:
                        arg = read<ushort>(ec.pc);
                        ec.pc += 2;
                        if (ec.ans != 0) {
                            ec.pc += (signed)arg;
                            if (ec.pc >= length) {
                                ec.err = ERR::BAD_JUMP;
                            }
                        }
                        break;
                    case OPC::BPOS:
                        arg = read<ushort>(ec.pc);
                        ec.pc += 2;
                        if (!ec.ans >> 31) {
                            ec.pc += (signed)arg;
                            if (ec.pc >= length) {
                                ec.err = ERR::BAD_JUMP;
                            }
                        }
                        break;
                    case OPC::BNEG:
                        arg = read<ushort>(ec.pc);
                        ec.pc += 2;
                        if (ec.ans >> 31) {
                            ec.pc += (signed)arg;
                            if (ec.pc >= length) {
                                ec.err = ERR::BAD_JUMP;
                            }
                        }
                        break;
                    default:
                        ec.err = ERR::INVALID_OPCODE;
                        break;
                }
            } while (ec.err == 0);
            return ec.err;
        }
    };

    class BytecodeFile {
        constexpr static const char HEADER[4] = {'B', 'B', 'L', 0x7F};
        const char *path;
        Bytecode data;
        uchar *filedata;
        public:
        BytecodeFile(const char *file) {
            path = file;
            FILE *fd;
            if ((fd = fopen(file, "rb"))) {
                fseek(fd, 0, 2);
                size_t length = ftell(fd);
                fseek(fd, 0, 0);
                filedata = (uchar*)malloc(length);
                fread(filedata, length, 1, fd);
                fclose(fd);
                size_t codelen = *(uint*)(&filedata[sizeof(HEADER)]);
                size_t cdatalen = *(uint*)(&filedata[sizeof(HEADER)+sizeof(uint)]);
                data = Bytecode(&filedata[sizeof(uint)*2+sizeof(HEADER)], codelen, &filedata[sizeof(uint)*2+sizeof(HEADER)+codelen], cdatalen);
            } else {
                filedata = nullptr;
            }
        }

        ~BytecodeFile() {
            if (filedata != nullptr) {
                free(filedata);
            }
        }

        int run() {
            if (filedata == nullptr) {
                return ERR::NO_FILE_DATA;
            }
            return data.execute();
        }
    };

}

#endif