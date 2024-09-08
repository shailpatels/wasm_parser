const std = @import("std");
const testing = std.testing;

export fn get_string() [*c]const u8 {
    const msg: [*c]const u8 = "hello world";
    return msg;
}
