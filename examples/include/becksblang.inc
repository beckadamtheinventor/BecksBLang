
macro bblprogram?
    local bblp
    bblp.data_count = 0
    bblp.var_count = 0
    macro code?
        macro var? lbl
            lbl := bblp.var_count
            bblp.var_count = bblp.var_count + 1
        end macro
        virtual at 0
        macro end?.code?
            load bblp.code: $-$$ from $$
            bblp.code.len := $-$$
            end virtual
            purge end?.code?
        end macro
    end macro
    macro data?
        virtual at 0
        macro str? lbl, s
            lbl := bblp.data_count
            bblp.data_count = bblp.data_count + 1
            dw 1 + lengthof s
            db s, 0
        end macro
        macro end?.data?
            dw 0
            load bblp.data: $-$$ from $$
            bblp.data.len := $-$$
            end virtual
            purge end?.data?
        end macro
    end macro
    macro end?.bblprogram?
        purge end?.bblprogram?
        purge code?
        purge data?
        db "BBL",$7F
        dd bblp.code.len
        if defined bblp.data
            dd bblp.data.len
        else
            dd 0
        end if
        db bblp.code
        if defined bblp.data
            db bblp.data
        end if
    end macro
end macro

virtual at 0
    O_NOP rb 1
    O_END rb 1
    O_STORE_VAR rb 1
    O_LOAD_VAR rb 1
    O_LOAD_IMM rb 1
    O_AND_VAR rb 1
    O_OR_VAR rb 1
    O_XOR_VAR rb 1
    O_NOT rb 1
    O_ITOF rb 1
    O_FTOI rb 1
    O_ADD_VAR rb 1
    O_SUB_VAR rb 1
    O_MUL_VAR rb 1
    O_DIV_VAR rb 1
    O_MOD_VAR rb 1
    O_NEG rb 1
    O_SIGN rb 1
    O_ABS rb 1
    O_FADD_VAR rb 1
    O_FSUB_VAR rb 1
    O_FMUL_VAR rb 1
    O_FDIV_VAR rb 1
    O_FMOD_VAR rb 1
    O_FNEG rb 1
    O_FSIGN rb 1
    O_FABS rb 1
    O_FPOW_VAR rb 1
    O_PRINT_NEWLINE rb 1
    O_PRINT_STR rb 1
    O_PRINT_INT rb 1
    O_PRINT_UINT rb 1
    O_PRINT_FLOAT rb 1
    O_PUSH rb 1
    O_POP rb 1
    O_CALL rb 1
    O_RETURN rb 1
    O_JUMP rb 1
    O_JREL rb 1
    O_BZERO rb 1
    O_BNZERO rb 1
    O_BPOS rb 1
    O_BNEG rb 1
end virtual

    O_EXT_GAMEOBJECT := $80

virtual at 0
    rb 1
    O_GO_SELECT_GAMEOBJECT rb 1
    O_GO_PRINT_GAMEOBJECT rb 1
    O_GO_GET_ACTIVE rb 1
    O_GO_SET_ACTIVE rb 1
    O_GO_GET_TRANSFORM_X rb 1
    O_GO_GET_TRANSFORM_Y rb 1
    O_GO_GET_TRANSFORM_Z rb 1
    O_GO_GET_TRANSFORM_RX rb 1
    O_GO_GET_TRANSFORM_RY rb 1
    O_GO_GET_TRANSFORM_RZ rb 1
    O_GO_GET_TRANSFORM_SX rb 1
    O_GO_GET_TRANSFORM_SY rb 1
    O_GO_GET_TRANSFORM_SZ rb 1
    O_GO_SET_TRANSFORM_X rb 1
    O_GO_SET_TRANSFORM_Y rb 1
    O_GO_SET_TRANSFORM_Z rb 1
    O_GO_SET_TRANSFORM_RX rb 1
    O_GO_SET_TRANSFORM_RY rb 1
    O_GO_SET_TRANSFORM_RZ rb 1
    O_GO_SET_TRANSFORM_SX rb 1
    O_GO_SET_TRANSFORM_SY rb 1
    O_GO_SET_TRANSFORM_SZ rb 1
end virtual

macro nop?
    db O_NOP
end macro

macro done?
    db O_END
end macro

macro store_var? vno
    db O_STORE_VAR
    dw vno
end macro

macro load_var? vno
    db O_LOAD_VAR
    dw vno
end macro

macro load_imm? val
    db O_LOAD_IMM
    dd val
end macro

macro and_var? vno
    db O_AND_VAR
    dw vno
end macro

macro or_var? vno
    db O_OR_VAR
    dw vno
end macro

macro xor_var? vno
    db O_XOR_VAR
    dw vno
end macro

macro not?
    db O_NOT
end macro

macro itof?
    db O_ITOF
end macro

macro ftoi?
    db O_FTOI
end macro

macro add_var? vno
    db O_ADD_VAR
    dw vno
end macro

macro sub_var? vno
    db O_SUB_VAR
    dw vno
end macro

macro mul_var? vno
    db O_MUL_VAR
    dw vno
end macro

macro div_var? vno
    db O_DIV_VAR
    dw vno
end macro

macro mod_var? vno
    db O_MOD_VAR
    dw vno
end macro

macro neg?
    db O_NEG
end macro

macro sign?
    db O_SIGN
end macro

macro abs?
    db O_ABS
end macro

macro fadd_var? vno
    db O_FADD_VAR
    dw vno
end macro

macro fsub_var? vno
    db O_FSUB_VAR
    dw vno
end macro

macro fmul_var? vno
    db O_FMUL_VAR
    dw vno
end macro

macro fdiv_var? vno
    db O_FDIV_VAR
    dw vno
end macro

macro fmod_var? vno
    db O_FMOD_VAR
    dw vno
end macro

macro fneg?
    db O_FNEG
end macro

macro fsign?
    db O_FSIGN
end macro

macro fabs?
    db O_FABS
end macro

macro fpow_var? vno
    db O_FPOW_VAR
    dw vno
end macro

macro print_newline?
    db O_PRINT_NEWLINE
end macro

macro print_str? sno
    db O_PRINT_STR
    dw sno
end macro

macro print_int?
    db O_PRINT_INT
end macro

macro print_uint?
    db O_PRINT_UINT
end macro

macro print_float?
    db O_PRINT_FLOAT
end macro

macro push?
    db O_PUSH
end macro

macro pop?
    db O_POP
end macro

macro call? addr
    db O_CALL
    dd addr
end macro

macro return?
    db O_RETURN
end macro

macro jump? addr
    db O_JUMP
    dd addr
end macro

macro jrel? addr
    db O_JREL
    dw addr - $ + 2
end macro

macro bzero? addr
    db O_BZERO
    dw addr - $ + 2
end macro

macro bnzero? addr
    db O_BNZERO
    dw addr - $ + 2
end macro

macro bneg? addr
    db O_BNEG
    dw addr - $ + 2
end macro

macro bpos? addr
    db O_BPOS
    dw addr - $ + 2
end macro
