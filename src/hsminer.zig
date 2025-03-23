const std = @import("std");
const zap = @import("zap");

pub const HSMiner = struct {
    pub var alloc: std.mem.Allocator = undefined;

    pub fn on_request(_: zap.Request) void {}
};
