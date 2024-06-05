const std = @import("std");
const Wasm = @import("wasm_structure.zig");

const assert = std.debug.assert;

/// Parse the WASM binary format based on https://webassembly.github.io/spec/core/binary/index.html
pub const Parser = struct {
    //not sure if having an error per specific area is more useful than a single overall section error
    const Error = error{
        BadHeader,
        BadSection,
        BadTypeSection,
        BadFunctionSection,
        BadMemorySection,
        BadGlobalSection,
        BadInstruction,
        BadExportSection,
        BadCodeSection,
        BadBlockType,
        BadDataSection,
        OutOfMemory,
    };

    //an input stream to the open wasm file
    reader: std.io.AnyReader,
    //where in the file we are
    current_position: usize = 0,
    //allocator
    allocator: std.mem.Allocator,
    //source of structure
    header: Wasm.Header = undefined,

    pub fn init(reader: std.io.AnyReader, allocator: std.mem.Allocator) Parser {
        return Parser{ .reader = reader, .allocator = allocator };
    }

    pub fn deinit(self: *Parser) void {
        defer self.header.sections.deinit();
        for (self.header.sections.items) |section| {
            deinitSection(section);
        }
    }

    fn deinitSection(section: Wasm.Section) void {
        switch (section.section_type) {
            .TYPE => {
                defer section.content.type.deinit();
                for (section.content.type.items) |function| {
                    function.params.deinit();
                    function.results.deinit();
                }
            },
            .FUNCTION => section.content.function.deinit(),
            .MEMORY => section.content.mem.deinit(),
            .GLOBAL => {
                defer section.content.global.deinit();
                for (section.content.global.items) |global| {
                    defer global.expression.instructions.deinit();
                    for (global.expression.instructions.items) |instr|
                        deinitInstruction(instr);
                }
            },
            .EXPORT => section.content.exports.deinit(),
            .CODE => {
                defer section.content.code.deinit();
                for (section.content.code.items) |code| {
                    defer code.functions.deinit();
                    for (code.functions.items) |func| {
                        func.declr.deinit();
                        deinitExpression(func.expression);
                    }
                }
            },
            .DATA => {
                defer section.content.data.deinit();
                for (section.content.data.items) |data| {
                    switch (data) {
                        inline .zero, .one, .two => |x| x.bytes.deinit(),
                    }
                    switch (data) {
                        inline .zero, .two => |x| deinitExpression(x.expr),
                        else => {},
                    }
                }
            },
            .CUSTOM => {
                section.content.custom.bytes.deinit();
            },
            else => {},
        }
    }

    fn deinitInstruction(instruction: Wasm.Instruction) void {
        switch (instruction) {
            .control => |control| {
                if (control.encoding == null)
                    return;

                const encoding = control.encoding.?;
                switch (encoding) {
                    .block_instruction => |block| {
                        defer block.instructions.deinit();
                        for (block.instructions.items) |instr| {
                            deinitInstruction(instr);
                        }
                    },
                    .br, .call_indir, .call => {},
                    else => unreachable,
                }
            },
            else => {},
        }
    }

    fn deinitExpression(expression: Wasm.Expression) void {
        defer expression.instructions.deinit();
        for (expression.instructions.items) |instr|
            deinitInstruction(instr);
    }

    pub fn parse(self: *Parser) !void {
        var buffer: [4096]u8 = undefined;
        //first try and read header
        var bytes_read = try self.readNBytes(&buffer, Wasm.Header.len);
        assert(bytes_read == Wasm.Header.len);
        self.current_position += buffer.len;

        var header = try self.ParseHeader(buffer[0..Wasm.Header.len]);
        std.debug.print("Reading version: {d}\n", .{header.version});

        //now parse sections
        var current_position: usize = 0;
        while (true) {
            const id = self.reader.readByte() catch break;
            const size = self.readU32();

            assert(id >= 0 and id <= 12);
            bytes_read = self.readNBytes(&buffer, size) catch break;

            assert(bytes_read == size);
            if (self.ParseSection(buffer[0..size], @enumFromInt(id))) |section| {
                try header.sections.append(section);
            } else |err| {
                std.debug.print("\n{!}\nSkipping Section\n\n", .{err});
            }

            current_position += bytes_read;
        }

        self.header = header;
    }

    ///Read the header into a struct, returns BadHeader err if magic number is not expected val
    ///data should be a buffer of 8 bytes
    fn ParseHeader(self: *Parser, data: []const u8) Error!Wasm.Header {
        assert(data.len == 8);

        //header starts with \0asm
        if (data[0] != 0 or data[1] != 'a' or data[2] != 's' or data[3] != 'm')
            return Error.BadHeader;

        //next comes the version
        return Wasm.Header{
            .sections = std.ArrayList(Wasm.Section).init(self.allocator),
            .version = @as(u32, data[4]) |
                @as(u32, data[5]) << 8 |
                @as(u32, data[6]) << 16 |
                @as(u32, data[7]) << 24,
        };
    }

    fn ParseSection(self: *Parser, data: []const u8, section_type: Wasm.Section.Types) Error!Wasm.Section {
        std.debug.print("Parsing {s} section of {d} bytes\n", .{ @tagName(section_type), data.len });
        var ret = Wasm.Section{
            .section_type = section_type,
            .content = undefined,
        };

        assert(data.len > 0);
        switch (section_type) {
            .TYPE => {
                var bytes_read: usize = 0;

                const num_functions = readU32FromSlice(data, &bytes_read) catch return Error.BadTypeSection;
                std.debug.print("num functions {d}\n", .{num_functions});

                ret.content = Wasm.Section.Content{ .type = std.ArrayList(Wasm.Function).init(self.allocator) };
                try ret.content.type.ensureTotalCapacity(num_functions);
                errdefer deinitSection(ret);

                var idx: u32 = 0;
                while (idx < num_functions) : (idx += 1) {
                    ret.content.type.appendAssumeCapacity(try self.ParseFunction(data[bytes_read..], &bytes_read));
                }

                assert(bytes_read == data.len);
            },
            .FUNCTION => {
                var bytes_read: usize = 0;
                const size = readU32FromSlice(data, &bytes_read) catch return Error.BadFunctionSection; // readU32(data[0]);

                std.debug.print("Function index count {d}\n", .{size});

                ret.content = Wasm.Section.Content{ .function = std.ArrayList(u32).init(self.allocator) };
                errdefer deinitSection(ret);
                var idx: usize = 0;
                assert(bytes_read + (size - 1) < data.len);

                while (idx < size) : (idx += 1) {
                    try ret.content.function.append(data[idx + bytes_read]);
                    std.debug.print("Function index at {d}\n", .{data[idx + bytes_read]});
                }

                assert(idx == data.len - 1);
            },
            .MEMORY => {
                var bytes_read: usize = 0;
                const size = readU32FromSlice(data, &bytes_read) catch return Error.BadMemorySection; // readU32(data[0]);
                std.debug.print("mem count {d}\n", .{size});

                assert(size + bytes_read < data.len);

                ret.content = Wasm.Section.Content{ .mem = std.ArrayList(Wasm.Section.Memory).init(self.allocator) };
                errdefer deinitSection(ret);
                var idx: usize = bytes_read;
                while (idx < size + bytes_read) : (idx += 1) {
                    assert(data[idx] == 0x00 or data[idx] == 0x01);
                    const is_max = (data[idx] == 0x01);

                    var local_read: usize = 0;
                    const min = readU32FromSlice(data[idx + 1 ..], &local_read) catch return Error.BadMemorySection;
                    std.debug.print("min {d}", .{min});
                    idx += local_read + 1;

                    var mem = Wasm.Section.Memory{ .min = min, .max = null };
                    if (is_max) {
                        const max = readU32FromSlice(data[idx..], &local_read) catch return Error.BadMemorySection;
                        mem.max = max;
                        std.debug.print(" max {d}\n", .{max});
                        idx += local_read;
                    } else {
                        std.debug.print("\n", .{});
                    }

                    try ret.content.mem.append(mem);
                }
            },
            .GLOBAL => {
                var bytes_read: usize = 0;
                const size = readU32FromSlice(data, &bytes_read) catch return Error.BadGlobalSection;
                std.debug.print("global count {d}\n", .{size});

                ret.content = Wasm.Section.Content{ .global = std.ArrayList(Wasm.Global).init(self.allocator) };
                errdefer deinitSection(ret);
                assert(bytes_read + (size - 1) < data.len);

                var idx: usize = 0;
                while (idx < size) : (idx += 1) {
                    assert(data[bytes_read + 1] == 0x01 or data[bytes_read + 1] == 0x00);
                    var local_read: usize = 0;
                    std.debug.print("starting at index {d}\n", .{bytes_read});
                    const global = Wasm.Global{
                        .val = Wasm.ValType.GetFromByte(data[bytes_read]) catch return Error.BadGlobalSection,
                        .is_mut = data[bytes_read + 1] == 0x01,
                        .expression = try self.ParseExpression(data[bytes_read + 2 ..], &local_read),
                    };

                    bytes_read += local_read;
                    std.debug.print("ending at index {d}\n", .{bytes_read});
                    idx += 1;
                    try ret.content.global.append(global);
                    std.debug.print("Global of type {s}, is_mut={}\n", .{ @tagName(global.val), global.is_mut });
                }
            },
            .EXPORT => {
                var bytes_read: usize = 0;
                const size = readU32FromSlice(data, &bytes_read) catch return Error.BadGlobalSection;

                var idx: usize = 0;
                ret.content = .{ .exports = std.ArrayList(Wasm.Export).init(self.allocator) };
                errdefer deinitSection(ret);
                while (idx < size) : (idx += 1) {
                    var next_bytes: usize = 0;
                    const name_size = readU32FromSlice(data[bytes_read..], &next_bytes) catch return Error.BadExportSection;

                    const name = data[bytes_read .. bytes_read + name_size + 1];
                    bytes_read += next_bytes + name_size;

                    assert(data[bytes_read] == 0x00 or data[bytes_read] == 0x01 or
                        data[bytes_read] == 0x02 or data[bytes_read] == 0x03 or data[bytes_read] == 0x04);

                    const index_type: Wasm.Index = switch (data[bytes_read]) {
                        0x00 => .FUNC,
                        0x01 => .TABLE,
                        0x02 => .MEM,
                        0x03 => .GLOBAL,
                        else => return Error.BadExportSection,
                    };

                    bytes_read += 1;
                    const index = readU32FromSlice(data[bytes_read..], &next_bytes) catch return Error.BadExportSection;
                    bytes_read += next_bytes;

                    const export_sec = Wasm.Export{ .name = name, .export_desc = .{ .index_type = index_type, .index = index } };
                    std.debug.print("Export name: {s}, index type {s} of {d}\n", .{ export_sec.name, @tagName(export_sec.export_desc.index_type), export_sec.export_desc.index });
                    try ret.content.exports.append(export_sec);
                }

                assert(bytes_read == data.len);
            },
            .CODE => {
                var bytes_read: usize = 0;
                const size = readU32FromSlice(data, &bytes_read) catch return Error.BadCodeSection;

                std.debug.print("{d} code entries\n", .{size});
                ret.content = .{ .code = std.ArrayList(Wasm.Code).init(self.allocator) };
                errdefer deinitSection(ret);

                var idx: usize = 0;
                while (idx < size) : (idx += 1) {
                    var code = Wasm.Code{ .functions = std.ArrayList(Wasm.Code.Local).init(self.allocator) };
                    errdefer code.functions.deinit();

                    var local_read: usize = 0;
                    std.debug.print("at {d}\n", .{bytes_read});
                    const code_size = readU32FromSlice(data[bytes_read..], &local_read) catch return Error.BadCodeSection;
                    bytes_read += local_read;
                    std.debug.print("size of code {d}\n", .{code_size});
                    //now the function
                    const num_locals = readU32FromSlice(data[bytes_read..], &local_read) catch return Error.BadCodeSection;
                    bytes_read += local_read;
                    std.debug.print("Num locals {d}\n", .{num_locals});

                    var local_idx: usize = 0;
                    var function = Wasm.Code.Local{
                        .declr = std.ArrayList(Wasm.ValType).init(self.allocator),
                        .expression = undefined,
                    };

                    while (local_idx < num_locals) : (local_idx += 1) {
                        const local_count = readU32FromSlice(data[bytes_read..], &local_read) catch return Error.BadCodeSection;
                        bytes_read += local_read;

                        std.debug.print("local count {d}\n", .{local_count});

                        var next_local_idx: usize = 0;
                        while (next_local_idx < local_count) : (next_local_idx += 1) {
                            const val_type = Wasm.ValType.GetFromByte(data[bytes_read]) catch return Error.BadCodeSection;
                            std.debug.print("val type of {s}\n", .{@tagName(val_type)});
                        }

                        //read the last local section, byte represents the actual param and num_locals is how many copies of it there are
                        bytes_read += 1;
                    }

                    //now parse the expression
                    local_read = 0;
                    const expr = try self.ParseExpression(data[bytes_read..], &local_read);
                    std.debug.print("total from expr {d}, so far {d}\n", .{ local_read, bytes_read });
                    function.expression = expr;

                    for (expr.instructions.items) |instruction| {
                        std.debug.print("{s}\n", .{@tagName(instruction.getOpCode())});
                        switch (instruction) {
                            .control => |control| {
                                if (control.encoding) |encoding| {
                                    switch (encoding) {
                                        .block_instruction => |bl| {
                                            for (bl.instructions.items) |i| {
                                                std.debug.print("\t{s}\n", .{@tagName(i.getOpCode())});
                                            }
                                        },
                                        else => {},
                                    }
                                }
                            },
                            else => {},
                        }
                    }

                    try code.functions.append(function);
                    try ret.content.code.append(code);
                    bytes_read += local_read;
                }
            },
            .DATA => {
                ret.content = .{ .data = std.ArrayList(Wasm.Data).init(self.allocator) };
                errdefer deinitSection(ret);

                var bytes_read: usize = 0;
                const num_data = readU32FromSlice(data, &bytes_read) catch return Error.BadDataSection;

                var num_idx: usize = 0;
                std.debug.print("Got {d} data sections\n", .{num_data});
                while (num_idx < num_data) : (num_idx += 1) {
                    var local_read: usize = 0;
                    const initial_integer = readU32FromSlice(data[bytes_read..], &local_read) catch return Error.BadDataSection;
                    bytes_read += local_read;

                    switch (initial_integer) {
                        0 => {
                            local_read = 0;
                            const expr = try self.ParseExpression(data[bytes_read..], &local_read);
                            bytes_read += local_read;

                            for (expr.instructions.items) |instr|
                                std.debug.print("instr of {s}\n", .{@tagName(instr.getOpCode())});

                            var new_data = Wasm.Data{ .zero = .{ .expr = expr, .bytes = std.ArrayList(u8).init(self.allocator) } };
                            local_read = 0;
                            const bytes = ParseBytesVec(data[bytes_read..], &local_read) catch return Error.BadDataSection;
                            bytes_read += local_read;

                            std.debug.print("byte array of '{s}'\n", .{bytes});
                            try new_data.zero.bytes.insertSlice(0, bytes);
                            try ret.content.data.append(new_data);
                        },
                        1 => {},
                        2 => {},
                        else => return Error.BadDataSection,
                    }
                }
            },
            .CUSTOM => {
                var bytes_read: usize = 0;
                const name = ParseBytesVec(data, &bytes_read) catch "";
                //the rest of the section are just the bytes
                ret.content = .{ .custom = .{
                    .name = name,
                    .bytes = std.ArrayList(u8).init(self.allocator),
                } };

                try ret.content.custom.bytes.insertSlice(0, data[bytes_read..]);
                std.debug.print("name: '{s}'\n", .{name});
            },
            //TODO
            else => {
                std.debug.print("Not handled {s}\n", .{@tagName(section_type)});
            },
        }

        return ret;
    }

    fn ParseBytesVec(data: []const u8, bytes_read: *usize) ![]const u8 {
        var local_read: usize = 0;
        const vec_size = try readU32FromSlice(data, &local_read);
        bytes_read.* += local_read;

        assert(vec_size < data.len);
        const slice = data[bytes_read.* .. bytes_read.* + vec_size];
        assert(slice.len == vec_size);

        bytes_read.* += vec_size;
        return slice;
    }

    fn ParseFunction(self: *Parser, data: []const u8, bytes_read: *usize) Error!Wasm.Function {
        assert(data.len > 1);
        if (data[0] != Wasm.Section.FUNCTION_BYTE)
            return Error.BadFunctionSection;

        const num_params: u32 = data[1];
        std.debug.print("num params {d}\n", .{num_params});
        assert(num_params + 1 < data.len);

        var ret = Wasm.Function{
            .params = std.ArrayList(Wasm.ValType).init(self.allocator),
            .results = std.ArrayList(Wasm.ValType).init(self.allocator),
        };

        try ret.results.ensureTotalCapacity(num_params);
        var current_position: usize = 2;
        var idx: u32 = 0;
        while (idx < num_params) : ({
            idx += 1;
            current_position += 1;
        }) {
            const param_type = Wasm.ValType.GetFromByte(data[current_position]) catch return Error.BadFunctionSection;
            ret.results.appendAssumeCapacity(param_type);
            std.debug.print("param type of {s}\n", .{@tagName(param_type)});
        }

        //now results
        assert(current_position < data.len);
        const num_results: u32 = data[current_position];
        std.debug.print("num results {d}\n", .{num_results});
        assert(current_position + num_results < data.len);

        try ret.results.ensureTotalCapacity(num_results);
        current_position += 1;
        idx = 0;
        while (idx < num_results) : ({
            idx += 1;
            current_position += 1;
        }) {
            const param_type = Wasm.ValType.GetFromByte(data[current_position]) catch return Error.BadFunctionSection;
            ret.results.appendAssumeCapacity(param_type);
            std.debug.print("param type of {s}\n", .{@tagName(param_type)});
        }

        bytes_read.* += current_position;
        return ret;
    }

    fn ParseExpression(self: *Parser, data: []const u8, bytes_read: *usize) Error!Wasm.Expression {
        var ret = Wasm.Expression{ .instructions = std.ArrayList(Wasm.Instruction).init(self.allocator) };
        errdefer ret.instructions.deinit();

        var local_read: usize = 0;
        while (bytes_read.* < data.len) {
            const instr = try self.ParseInstruction(data[bytes_read.*..], &local_read);
            try ret.instructions.append(instr);
            bytes_read.* += local_read;

            if (data[bytes_read.*] == 0x0B)
                break;
        }

        assert(data[bytes_read.*] == 0x0B);
        //consume the 0x0B
        bytes_read.* += 1;
        return ret;
    }

    fn ParseInstruction(self: *Parser, data: []const u8, total_read: *usize) Error!Wasm.Instruction {
        var idx: usize = 0;
        const opcode = Wasm.Instruction.OpCode.GetFromByte(data[idx]) catch return Error.BadInstruction;

        switch (data[idx]) {
            0x00...0x11 => {
                //control instructions
                const char = data[idx];
                switch (char) {
                    0x02...0x04 => {
                        idx += 1;
                        var bytes_read: usize = 0;
                        const block_type = ParseBlockType(data[idx..], &bytes_read) catch return Error.BadInstruction;
                        idx += bytes_read;

                        var ret = Wasm.Instruction{
                            .control = .{ .opcode = opcode, .encoding = .{ .block_instruction = .{
                                .block_type = block_type,
                                .instructions = std.ArrayList(Wasm.Instruction).init(self.allocator),
                            } } },
                        };
                        errdefer {
                            defer ret.control.encoding.?.block_instruction.instructions.deinit();
                            for (ret.control.encoding.?.block_instruction.instructions.items) |instr|
                                deinitInstruction(instr);
                        }

                        while (idx < data.len and data[idx] != 0x0B and data[idx] != 0x05) {
                            const instr_1 = self.ParseInstruction(data[idx..], &bytes_read) catch return Error.BadInstruction;
                            idx += bytes_read;

                            try ret.control.encoding.?.block_instruction.instructions.append(instr_1);
                        }

                        if (data[idx] == 0x05) {
                            while (idx < data.len and data[idx] != 0x0B) {
                                _ = self.ParseInstruction(data[idx..], &bytes_read) catch return Error.BadInstruction;
                                idx += bytes_read;
                            }
                        }

                        //consume the 0x0B
                        idx += 1;

                        total_read.* = idx;
                        return ret;
                    },
                    else => {},
                }

                switch (char) {
                    0x0C, 0x0D => {
                        idx += 1;
                        var local_read: usize = 0;
                        const index = readU32FromSlice(data[idx..], &local_read) catch return Error.BadInstruction;
                        const ret = Wasm.Instruction{
                            .control = .{ .encoding = .{ .br = index }, .opcode = opcode },
                        };

                        total_read.* = idx + local_read;
                        return ret;
                    },
                    else => {},
                }

                switch (char) {
                    0x10 => {
                        idx += 1;
                        var local_read: usize = 0;
                        const func_idx = readU32FromSlice(data[idx..], &local_read) catch return Error.BadInstruction;
                        idx += local_read;

                        const ret = Wasm.Instruction{
                            .control = .{ .encoding = .{ .call = func_idx }, .opcode = opcode },
                        };

                        total_read.* = idx;
                        return ret;
                    },
                    else => {},
                }

                if (char != 0x00 and char != 0x01 and char != 0x0F) {
                    std.debug.print("unhandled char {x}\n", .{char});
                    return Error.BadInstruction;
                }

                total_read.* = 1;
                return Wasm.Instruction{ .control = .{ .opcode = opcode } };
            },
            0x20...0x24 => {
                idx += 1;
                var local_read: usize = 0;
                const index = readU32FromSlice(data[idx..], &local_read) catch return Error.BadInstruction;

                total_read.* = local_read + 1;
                return Wasm.Instruction{ .variable = .{ .opcode = opcode, .index = index } };
            },
            0x28...0x40 => {
                idx += 1;
                var local_read: usize = 0;
                const a = readU32FromSlice(data[idx..], &local_read) catch return Error.BadInstruction;
                idx += local_read;
                const o = readU32FromSlice(data[idx..], &local_read) catch return Error.BadInstruction;
                idx += local_read;

                total_read.* = idx;
                return Wasm.Instruction{ .memory = .{ .opcode = opcode, .@"align" = a, .offset = o } };
            },
            0x41, 0x42, 0x43, 0x44 => |char| {
                var ret = Wasm.Instruction{ .numeric = .{ .value = null, .opcode = opcode } };
                //numeric load instructions with a single operand
                idx += 1;
                var bytes_read: usize = 0;

                //now read the value
                switch (char) {
                    0x41 => ret.numeric.value = .{ .i32 = readSignedLEB128(i32, data[idx..], &bytes_read) catch return Error.BadInstruction },
                    0x42 => ret.numeric.value = .{ .i64 = readSignedLEB128(i64, data[idx..], &bytes_read) catch return Error.BadInstruction },
                    0x43 => {
                        bytes_read = 4;
                        ret.numeric.value = .{ .f32 = readFloatFromBytes(f32, data[idx..]) };
                    },
                    0x44 => {
                        bytes_read = 8;
                        ret.numeric.value = .{ .f64 = readFloatFromBytes(f64, data[idx..]) };
                    },
                    else => unreachable,
                }

                std.debug.print("opcode of {s} ", .{@tagName(ret.numeric.opcode)});
                switch (char) {
                    0x41 => std.debug.print("value of {d}\n", .{ret.numeric.value.?.i32}),
                    0x42 => std.debug.print("value of {d}\n", .{ret.numeric.value.?.i64}),
                    0x43 => std.debug.print("value of {d}\n", .{ret.numeric.value.?.f32}),
                    0x44 => std.debug.print("value of {d}\n", .{ret.numeric.value.?.f64}),
                    else => unreachable,
                }

                total_read.* = bytes_read + idx;
                return ret;
            },
            0x45...0xC4 => {
                //numeric instructions with no operands
                total_read.* = 1;
                return Wasm.Instruction{ .numeric = .{ .value = null, .opcode = opcode } };
            },
            else => {
                std.debug.print("unhandled instruction {x}\n", .{data[0]});
                return Error.BadInstruction;
            },
        }
    }

    fn ParseBlockType(data: []const u8, bytes_read: *usize) Error!Wasm.Instruction.BlockType {
        bytes_read.* = 1;
        if (data[0] == 0x40)
            return Wasm.Instruction.BlockType{ .empty = void{} };

        //try to see if its a valtype
        const val_maybe = Wasm.ValType.GetFromByte(data[0]);
        if (val_maybe) |val| {
            return Wasm.Instruction.BlockType{ .value = val };
        } else |_| {
            //try to see if its a signed integer
            const s33 = readSignedLEB128(i33, data, bytes_read) catch return Error.BadBlockType;
            return Wasm.Instruction.BlockType{ .type_index = s33 };
        }
    }

    //helper function to read a specific number of bytes
    fn readNBytes(self: Parser, buffer: []u8, len: usize) anyerror!usize {
        assert(len <= buffer.len);
        return try self.reader.read(buffer[0..len]);
    }

    ///https://en.wikipedia.org/wiki/LEB128
    fn readU32(self: *Parser) u32 {
        var result: u32 = 0;
        var shift: std.math.Log2Int(u32) = 0;

        while (true) {
            const byte = self.reader.readByte() catch return result;
            result |= @as(u32, byte & 0x7f) << shift;
            if (byte & 0x80 == 0)
                break;
            shift += 7;
        }

        return result;
    }

    fn readU32FromSlice(data: []const u8, bytes_read: *usize) error{Overflow}!u32 {
        var result: u32 = 0;
        var shift: std.math.Log2Int(u32) = 0;

        for (data, 0..) |byte, index| {
            const shift_result = @shlWithOverflow(@as(u32, (byte & 0x7f)), shift);
            if (shift_result[1] != 0)
                return error.Overflow;

            result |= shift_result[0];
            if (byte & 0x80 == 0) {
                bytes_read.* = (index + 1);
                return result;
            }

            shift += 7;
        }

        return error.Overflow;
    }

    //https://en.wikipedia.org/wiki/LEB128
    //https://github.com/ziglang/zig/blob/759c2211c2eba44cccf0608267bf1a05934ad8a1/lib/std/leb128.zig#L55
    //read a LEB128 encoded signed value from a slice, bytes_read will be set with how much of the slice was read
    fn readSignedLEB128(comptime T: type, data: []const u8, bytes_read: *usize) error{Overflow}!T {
        var result: T = 0;
        var shift: std.math.Log2Int(T) = 0;
        const shift_max = if (T == i64) 64 else 32;

        for (data, 0..) |byte, index| {
            const shift_result = @shlWithOverflow(@as(T, (byte & 0x7f)), shift);
            if (shift_result[1] != 0)
                return error.Overflow;

            result |= shift_result[0];
            if (byte & 0x80 == 0) {
                bytes_read.* = (index + 1);
                //handle if value is negative
                if (shift < shift_max and @as(T, byte & 0x40) != 0) {
                    const neg_shift = @shlWithOverflow(@as(T, 1), shift);
                    if (neg_shift[1] != 0)
                        return error.Overflow;

                    result |= -neg_shift[0];
                }

                return result;
            }

            shift += 7;
        }

        return error.Overflow;
    }

    fn readFloatFromBytes(comptime T: type, data: []const u8) T {
        if (T == f32) {
            return @bitCast(@as(u32, data[0]) |
                @as(u32, data[1]) << 8 |
                @as(u32, data[2]) << 16 |
                @as(u32, data[3]) << 24);
        } else if (T == f64) {
            return @bitCast(@as(u64, data[0]) |
                @as(u64, data[1]) << 8 |
                @as(u64, data[2]) << 16 |
                @as(u64, data[3]) << 24 |
                @as(u64, data[4]) << 32 |
                @as(u64, data[5]) << 40 |
                @as(u64, data[6]) << 48 |
                @as(u64, data[7]) << 56);
        } else {
            @compileError("readFloatFromBytes expected f32 or f64, got " ++ @typeName(T));
        }
    }
};

test "readU32FromSlice" {
    {
        const data = [_]u8{ 0xE5, 0x8E, 0x26 };
        var bytes_read: usize = 0;
        const result = Parser.readU32FromSlice(&data, &bytes_read);
        try std.testing.expectEqual(624485, result);
        try std.testing.expectEqual(data.len, bytes_read);
    }

    {
        const data = [_]u8{ 0x9d, 0x01 };
        var bytes_read: usize = 0;
        const result = Parser.readU32FromSlice(&data, &bytes_read);
        try std.testing.expectEqual(157, result);
        try std.testing.expectEqual(data.len, bytes_read);
    }
}
