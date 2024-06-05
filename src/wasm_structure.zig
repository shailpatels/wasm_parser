const std = @import("std");

pub const Header = struct {
    pub const len: u16 = 8;

    version: u32,
    sections: std.ArrayList(Section),
};

pub const Section = struct {
    pub const FUNCTION_BYTE = 0x60;

    section_type: Types,
    content: Content,

    pub const Content = union {
        type: std.ArrayList(Function),
        function: std.ArrayList(u32),
        mem: std.ArrayList(Memory),
        global: std.ArrayList(Global),
        exports: std.ArrayList(Export),
        code: std.ArrayList(Code),
        data: std.ArrayList(Data),
        custom: Custom,
    };
    //section types, the IDs start at 0 and increment upwards
    pub const Types = enum {
        CUSTOM,
        TYPE,
        IMPORT,
        FUNCTION,
        TABLE,
        MEMORY,
        GLOBAL,
        EXPORT,
        START,
        ELEMENT,
        CODE,
        DATA,
        DATA_COUNT,
    };

    pub const Memory = struct {
        min: u32,
        max: ?u32,
    };
};

pub const Function = struct {
    params: std.ArrayList(ValType),
    results: std.ArrayList(ValType),
};

pub const Global = struct {
    val: ValType,
    is_mut: bool,
    expression: Expression,
};

pub const Code = struct {
    functions: std.ArrayList(Local),

    pub const Local = struct {
        declr: std.ArrayList(ValType),
        expression: Expression,
    };
};

pub const Data = union(enum) {
    zero: Zero,
    one: One,
    two: Two,

    //mode active, memory: 0, offset: expr
    const Zero = struct {
        expr: Expression,
        bytes: std.ArrayList(u8),
    };

    //mode passive
    const One = struct {
        bytes: std.ArrayList(u8),
    };

    //mode active, memory: memidx, offset: expr
    const Two = struct {
        memidx: u32,
        expr: Expression,
        bytes: std.ArrayList(u8),
    };
};

pub const Export = struct {
    name: []const u8,
    export_desc: struct {
        index: u32,
        index_type: Index,
    },
};

pub const Custom = struct {
    name: []const u8,
    bytes: std.ArrayList(u8),
};

pub const Index = enum {
    TYPE,
    FUNC,
    TABLE,
    MEM,
    GLOBAL,
    ELEM,
    DATA,
    LOCAL,
    LABEL,
};

pub const ValType = enum {
    I32,
    I64,
    F32,
    F64,
    VEC,
    REF,

    pub fn GetFromByte(char: u8) error{UnknownType}!ValType {
        return switch (char) {
            0x7F => .I32,
            0x7E => .I64,
            0x7D => .F32,
            0x7C => .F64,
            0x7b => .VEC,
            0x70, 0x6F => .REF,
            else => error.UnknownType,
        };
    }
};

pub const Expression = struct {
    instructions: std.ArrayList(Instruction),
};

pub const Instruction = union(enum) {
    numeric: Numeric,
    control: Control,
    variable: Variable,
    memory: Memory,

    pub const Numeric = struct {
        opcode: OpCode,
        //value can either be i32,i64,f32,f64 based on opcode
        value: ?union {
            i64: i64,
            i32: i32,
            f64: f64,
            f32: f32,
        },
    };

    //control instructions have varying encodings
    pub const Control = struct {
        opcode: OpCode,

        encoding: ?Encoding = null,

        pub const Encoding = union(enum) {
            block_instruction: BlockInstruction,
            block_2instruction: Block2Instruction,
            br: u32,
            br_table: BrTable,
            call: u32,
            call_indir: CallIndir,
        };

        pub const BlockInstruction = struct {
            block_type: BlockType,
            instructions: std.ArrayList(Instruction),
        };

        pub const Block2Instruction = struct {
            block_type: BlockType,
            instruction_1: std.ArrayList(Instruction),
            instruction_2: std.ArrayList(Instruction),
        };

        pub const BrTable = struct {
            label_indexes: std.ArrayList(u32),
            label_idx: u32,
        };

        pub const CallIndir = struct {
            type_idx: u32,
            table_idx: u32,
        };
    };

    pub const Variable = struct {
        opcode: OpCode,
        index: u32,
    };

    pub const Memory = struct {
        opcode: OpCode,

        @"align": u32,
        offset: u32,
    };

    pub const BlockType = union(enum) {
        empty: void,
        value: ValType,
        type_index: i33,
    };

    pub fn getOpCode(self: Instruction) OpCode {
        return switch (self) {
            inline .numeric, .control, .variable, .memory => |i| i.opcode,
        };
    }

    pub const OpCode = enum(u8) {
        pub fn GetFromByte(char: u8) error{InvalidEnumTag}!OpCode {
            return try std.meta.intToEnum(OpCode, char);
        }

        UNREACHABLE = 0x00,
        NOP = 0x01,
        BLOCK = 0x02,
        LOOP = 0x03,
        IF_ELSE = 0x04,
        BR = 0x0C,
        BR_IF = 0x0D,
        BR_TABLE = 0x0E,
        RETURN = 0x0F,
        CALL = 0x10,
        CALL_INDIRECT = 0x11,

        LOCAL_GET = 0x20,
        LOCAL_SET = 0x21,
        LOCAL_TEE = 0x22,
        GLOBAL_GET = 0x23,
        GLOBAL_SET = 0x24,

        I32_LOAD = 0x28,
        I64_LOAD = 0x29,
        F32_LOAD = 0x2A,
        F64_LOAD = 0x2B,
        I32_LOAD8_S = 0x2C,
        I32_LOAD8_U = 0x2D,
        I32_LOAD16_S = 0x2E,
        I32_LOAD16_U = 0x2F,
        I64_LOAD8_S = 0x30,
        I64_LOAD8_U = 0x31,
        I64_LOAD16_S = 0x32,
        I64_LOAD16_U = 0x33,
        I64_LOAD32_S = 0x34,
        I64_LOAD32_U = 0x35,
        I32_STORE = 0x36,
        I64_STORE = 0x37,
        F32_STORE = 0x38,
        F64_STORE = 0x39,
        I32_STORE8 = 0x3A,
        I32_STORE16 = 0x3B,
        I64_STORE8 = 0x3C,
        I64_STORE16 = 0x3D,
        I64_STORE32 = 0x3E,
        MEMORY_SIZE = 0x3F,
        MEMORY_GROW = 0x40,

        //0xFC maps to MEMORY_SIZE, MEMORY_GROW, MEMORY_INIT, DATA_DROP, MEMORY_COPY, MEMORY_FILL
        MEMORY_OPTS = 0xFC,

        I32_CONST = 0x41,
        I64_CONST = 0x42,
        F32_CONST = 0x43,
        F64_CONST = 0x44,

        I32_EQZ = 0x45,
        I32_EQ = 0x46,
        I32_NE = 0x47,
        I32_LT_S = 0x48,
        I32_LT_U = 0x49,
        I32_GT_S = 0x4A,
        I32_GT_U = 0x4B,
        I32_LE_S = 0x4C,
        I32_LE_U = 0x4D,
        I32_GE_S = 0x4E,
        I32_GE_U = 0x4F,

        I64_EQZ = 0x50,
        I64_EQ = 0x51,
        I64_NE = 0x52,
        I64_LT_S = 0x53,
        I64_LT_U = 0x54,
        I64_GT_S = 0x55,
        I64_GT_U = 0x56,
        I64_LE_S = 0x57,
        I64_LE_U = 0x58,
        I64_GE_S = 0x59,
        I64_GE_U = 0x5A,

        F32_EQ = 0x5B,
        F32_NE = 0x5C,
        F32_LT = 0x5D,
        F32_GT = 0x5E,
        F32_LE = 0x5F,
        F32_GE = 0x60,

        F64_EQ = 0x61,
        F64_NE = 0x62,
        F64_LT = 0x63,
        F64_GT = 0x64,
        F64_LE = 0x65,
        F64_GE = 0x66,

        I32_CLZ = 0x67,
        I32_CTZ = 0x68,
        I32_POPCNT = 0x69,
        I32_ADD = 0x6A,
        I32_SUB = 0x6B,
        I32_MUL = 0x6C,
        I32_DIV_S = 0x6D,
        I32_DIV_U = 0x6E,
        I32_REM_S = 0x6F,
        I32_REM_U = 0x70,
        I32_AND = 0x71,
        I32_OR = 0x72,
        I32_XOR = 0x73,
        I32_SHL = 0x74,
        I32_SHR_S = 0x75,
        I32_SHR_U = 0x76,
        I32_ROTL = 0x77,
        I32_ROTR = 0x78,

        I64_CLZ = 0x79,
        I64_CTZ = 0x7A,
        I64_POPCNT = 0x7B,
        I64_ADD = 0x7C,
        I64_SUB = 0x7D,
        I64_MUL = 0x7E,
        I64_DIV_S = 0x7F,
        I64_DIV_U = 0x80,
        I64_REM_S = 0x81,
        I64_REM_U = 0x82,
        I64_AND = 0x83,
        I64_OR = 0x84,
        I64_XOR = 0x85,
        I64_SHL = 0x86,
        I64_SHR_S = 0x87,
        I64_SHR_U = 0x88,
        I64_ROTL = 0x89,
        I64_ROTR = 0x8A,

        F32_ABS = 0x8B,
        F32_NEG = 0x8C,
        F32_CEIL = 0x8D,
        F32_FLOOR = 0x8E,
        F32_TRUNC = 0x8F,
        F32_NEAREST = 0x90,
        F32_SQRT = 0x91,
        F32_ADD = 0x92,
        F32_SUB = 0x93,
        F32_MUL = 0x94,
        F32_DIV = 0x95,
        F32_MIN = 0x96,
        F32_MAX = 0x97,
        F32_COPYSIGN = 0x98,

        F64_ABS = 0x99,
        F64_NEG = 0x9A,
        F64_CEIL = 0x9B,
        F64_FLOOR = 0x9C,
        F64_TRUNC = 0x9D,
        F64_NEAREST = 0x9E,
        F64_SQRT = 0x9F,
        F64_ADD = 0xA0,
        F64_SUB = 0xA1,
        F64_MUL = 0xA2,
        F64_DIV = 0xA3,
        F64_MIN = 0xA4,
        F64_MAX = 0xA5,
        F64_COPYSIGN = 0xA6,

        I32_WRAP_I64 = 0xA7,
        I32_TRUNC_F32_S = 0xA8,
        I32_TRUNC_F32_U = 0xA9,
        I32_TRUNC_F64_S = 0xAA,
        I32_TRUNC_F64_U = 0xAB,
        I64_EXTEND_I32_S = 0xAC,
        I64_EXTEND_I32_U = 0xAD,
        I64_TRUNC_F32_S = 0xAE,
        I64_TRUNC_F32_U = 0xAF,
        I64_TRUNC_F64_S = 0xB0,
        I64_TRUNC_F64_U = 0xB1,
        F32_CONVERT_I32_S = 0xB2,
        F32_CONVERT_I32_U = 0xB3,
        F32_CONVERT_I64_S = 0xB4,
        F32_CONVERT_I64_U = 0xB5,
        F32_DEMOTE_F64 = 0xB6,
        F64_CONVERT_I32_S = 0xB7,
        F64_CONVERT_I32_U = 0xB8,
        F64_CONVERT_I64_S = 0xB9,
        F64_CONVERT_I64_U = 0xBA,
        F64_PROMOTE_F32 = 0xBB,
        I32_REINTERPRET_F32 = 0xBC,
        I64_REINTERPRET_F64 = 0xBD,
        F32_REINTERPRET_I32 = 0xBE,
        F64_REINTERPRET_I64 = 0xBF,

        I32_EXTEND8_S = 0xC0,
        I32_EXTEND16_S = 0xC1,
        I64_EXTEND8_S = 0xC2,
        I64_EXTEND16_S = 0xC3,
        I64_EXTEND32_S = 0xC4,
    };
};
