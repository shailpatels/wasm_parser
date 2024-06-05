const std = @import("std");
const Parser = @import("parser.zig").Parser;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();

    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();
    //skip program name
    _ = args.skip();

    const tgt_filename = args.next();
    if (tgt_filename == null) {
        std.debug.print("Expected usage ./wrt <filename>\n", .{});
        return;
    }

    var file = try std.fs.cwd().openFile(tgt_filename.?, .{});
    defer file.close();

    var buf_reader = std.io.bufferedReader(file.reader());
    const in_stream = buf_reader.reader().any();

    var parser = Parser.init(in_stream, allocator);
    defer parser.deinit();
    try parser.parse();
}
