const c = @cImport({
    @cInclude("pkcs11zig.h");
});
const std = @import("std");
const zap = @import("zap");

const index = @embedFile("index.mustache");
const favicon = @embedFile("favicon.ico");

const Self = @This();

const Slot = struct {
    description: [64]u8,
    label: [32]u8,
    model: [16]u8,
    initialized: bool,
};

allocator: std.mem.Allocator,
sym: *c.CK_FUNCTION_LIST,
manufacturer_id: [32]u8,
slots: []Slot,
template: zap.Mustache,

pub fn init(allocator: std.mem.Allocator, sym: *c.CK_FUNCTION_LIST) !Self {
    var args: c.CK_C_INITIALIZE_ARGS = .{ .flags = c.CKF_OS_LOCKING_OK };
    _ = sym.C_Initialize.?(&args);

    var info: c.CK_INFO = undefined;
    _ = sym.C_GetInfo.?(&info);

    var slot_count: c.CK_ULONG = undefined;
    _ = sym.C_GetSlotList.?(c.CK_TRUE, null, &slot_count);

    const slot_list = try allocator.alloc(c.CK_ULONG, slot_count);
    defer allocator.free(slot_list);
    _ = sym.C_GetSlotList.?(c.CK_TRUE, slot_list.ptr, &slot_count);

    const slots = try allocator.alloc(Slot, slot_count);
    errdefer allocator.free(slots);

    for (0.., slot_list) |i, slot| {
        var slot_info: c.CK_SLOT_INFO = undefined;
        _ = sym.C_GetSlotInfo.?(slot, &slot_info);

        var token_info: c.CK_TOKEN_INFO = undefined;
        _ = sym.C_GetTokenInfo.?(slot, &token_info);

        slots[i] = .{
            .description = slot_info.slotDescription,
            .label = token_info.label,
            .model = token_info.model,
            .initialized = (token_info.flags & c.CKF_TOKEN_INITIALIZED) == c.CKF_TOKEN_INITIALIZED,
        };
    }

    return .{
        .allocator = allocator,
        .sym = sym,
        .manufacturer_id = info.manufacturerID,
        .slots = slots,
        .template = try zap.Mustache.fromData(index),
    };
}

pub fn deinit(self: *Self) void {
    self.allocator.free(self.slots);
    self.template.deinit();
}

pub fn getIndex(self: *Self, req: zap.Request) void {
    const ret = self.template.build(.{
        .manufacturer_id = self.manufacturer_id,
        .slots = self.slots,
    });
    defer ret.deinit();

    req.sendBody(ret.str().?) catch return;
}

pub fn getFavicon(_: *Self, req: zap.Request) void {
    req.setContentTypeFromPath() catch return;
    req.sendBody(favicon) catch return;
}
