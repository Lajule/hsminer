const c = @cImport({
    @cInclude("pkcs11zig.h");
});
const std = @import("std");
const zap = @import("zap");

const index = @embedFile("index.mustache");
const favicon = @embedFile("favicon.ico");
const script = @embedFile("script.js");
const style = @embedFile("style.css");

const Self = @This();

allocator: std.mem.Allocator,
sym: *c.CK_FUNCTION_LIST,
manufacturer_id: [32]u8,
slot_count: c_ulong,
template: zap.Mustache,

pub fn init(allocator: std.mem.Allocator, sym: *c.CK_FUNCTION_LIST) !Self {
    var args: c.CK_C_INITIALIZE_ARGS = .{ .flags = c.CKF_OS_LOCKING_OK };
    _ = sym.C_Initialize.?(&args);

    var info: c.CK_INFO = undefined;
    _ = sym.C_GetInfo.?(&info);

    var slot_count: c.CK_ULONG = undefined;
    _ = sym.C_GetSlotList.?(c.CK_TRUE, null, &slot_count);

    return .{
        .allocator = allocator,
        .sym = sym,
        .manufacturer_id = info.manufacturerID,
        .slot_count = slot_count,
        .template = try zap.Mustache.fromData(index),
    };
}

pub fn deinit(self: *Self) void {
    self.template.deinit();
}

pub fn getIndex(self: *Self, req: zap.Request) void {
    const slot_count: i32 = @intCast(self.slot_count);
    const ret = self.template.build(.{
        .manufacturer_id = self.manufacturer_id,
        .slot_count = slot_count,
    });
    defer ret.deinit();

    req.sendBody(ret.str().?) catch return;
}

pub fn getFavicon(_: *Self, req: zap.Request) void {
    req.setContentTypeFromPath() catch return;
    req.sendBody(favicon) catch return;
}

pub fn getScript(_: *Self, req: zap.Request) void {
    req.setContentTypeFromPath() catch return;
    req.sendBody(script) catch return;
}

pub fn getStyle(_: *Self, req: zap.Request) void {
    req.setContentTypeFromPath() catch return;
    req.sendBody(style) catch return;
}
