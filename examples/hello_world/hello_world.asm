
include "../include/becksblang.inc"

bblprogram
    ; start of executable code
    code
        var temp1
        _main:
            print_str   s_HelloWorld
            print_newline
            print_newline
            print_str   s_Testing
            print_newline
        ; test 1
            print_str   s_Formula1
            load_imm    1
            store_var   temp1
            add_var     temp1
            print_uint
            print_newline
        ; test 2
            print_str   s_Formula2
            load_imm    11
            store_var   temp1
            load_imm    5
            sub_var     temp1
            print_int
            print_newline
        ; test 3
            print_str   s_Formula3
            load_imm    5
            store_var   temp1
            load_imm    8
            mul_var     temp1
            print_uint
            print_newline
        ; test 4
            print_str   s_Formula4
            load_imm    20
            itof
            store_var   temp1
            load_imm    1
            itof
            fdiv_var     temp1
            print_float
            print_newline
        ; test 5
            print_str   s_Formula5
            load_imm    5
            store_var   temp1
            load_imm    53
            mod_var     temp1
            print_uint
            print_newline

            done

    end code
    ; start of data
    data
        str s_HelloWorld, "Hello World!"
        str s_Testing, "Testing Operations"
        str s_Formula1, "1+1="
        str s_Formula2, "5-11="
        str s_Formula3, "8*5="
        str s_Formula4, "1/20="
        str s_Formula5, "53%5="
    end data
end bblprogram
