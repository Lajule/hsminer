const c = @cImport({
    @cInclude("pkcs11zig.h");
});
const std = @import("std");
const zap = @import("zap");

const index = @embedFile("index.mustache");
const favicon = @embedFile("favicon.ico");

const Self = @This();

allocator: std.mem.Allocator,
template: zap.Mustache,
sym: *c.CK_FUNCTION_LIST,
info: c.CK_INFO,
slot_list: []c.CK_ULONG,
slot_infos: []c.CK_SLOT_INFO,
session_handle: c.CK_SESSION_HANDLE,

pub fn init(allocator: std.mem.Allocator, sym: *c.CK_FUNCTION_LIST) !Self {
    var args: c.CK_C_INITIALIZE_ARGS = .{ .flags = c.CKF_OS_LOCKING_OK };
    _ = sym.C_Initialize.?(&args);

    var info: c.CK_INFO = undefined;
    _ = sym.C_GetInfo.?(&info);

    var slot_count: c.CK_ULONG = undefined;
    _ = sym.C_GetSlotList.?(c.CK_TRUE, null, &slot_count);

    const slot_list = try allocator.alloc(c.CK_ULONG, slot_count);
    errdefer allocator.free(slot_list);
    _ = sym.C_GetSlotList.?(c.CK_TRUE, slot_list.ptr, &slot_count);

    const slot_infos = try allocator.alloc(c.CK_SLOT_INFO, slot_count);
    errdefer allocator.free(slot_infos);

    const token_infos = try allocator.alloc(c.CK_TOKEN_INFO, slot_count);
    errdefer allocator.free(token_infos);

    for (slot_list, 0..) |slot, i| {
        _ = sym.C_GetSlotInfo.?(slot, &slot_infos[i]);
    }

    return .{
        .allocator = allocator,
        .template = try zap.Mustache.fromData(index),
        .sym = sym,
        .info = info,
        .slot_list = slot_list,
        .slot_infos = slot_infos,
        .session_handle = 0,
    };
}

pub fn deinit(self: *Self) void {
    self.allocator.free(self.slot_list);
    self.allocator.free(self.slot_infos);

    self.template.deinit();
}

pub fn getIndex(self: *Self, req: zap.Request) void {
    const Slot = struct {
        slot_id: isize,
        description: [64]u8,
    };

    const slots = self.allocator.alloc(Slot, self.slot_list.len) catch return;
    defer self.allocator.free(slots);

    for (self.slot_list, 0..) |slot_id, i| {
        slots[i].slot_id = @intCast(slot_id);
        slots[i].description = self.slot_infos[i].slotDescription;
    }

    const ret = self.template.build(.{
        .manufacturer_id = self.info.manufacturerID,
        .slots = slots,
        .logged = self.session_handle != 0,
    });
    defer ret.deinit();

    req.sendBody(ret.str().?) catch return;
}

pub fn postLogin(self: *Self, req: zap.Request) void {
    req.parseBody() catch return;

    const params = req.parametersToOwnedList(self.allocator, false) catch return;
    defer params.deinit();

    var slot_id: isize = 0;
    var pin: isize = 0;

    for (params.items) |kv| {
        if (kv.value) |v| {
            if (std.mem.eql(u8, "slot_id", kv.key.str)) {
                slot_id = v.Int;
                continue;
            }

            if (std.mem.eql(u8, "pin", kv.key.str)) {
                switch (v) {
                    .Int => |p| pin = p,
                    else => {},
                }
                continue;
            }
        }
    }

    _ = self.sym.C_OpenSession.?(@intCast(slot_id), c.CKF_RW_SESSION | c.CKF_SERIAL_SESSION, null, null, &self.session_handle);
    std.log.debug("session_handle: {}", .{self.session_handle});

    var buf: [255]u8 = undefined;
    const str_pin = std.fmt.bufPrint(&buf, "{}", .{pin}) catch return;
    _ = self.sym.C_Login.?(self.session_handle, c.CKU_USER, str_pin.ptr, str_pin.len);

    req.redirectTo("/", null) catch return;
}

pub fn postLogout(self: *Self, req: zap.Request) void {
    _ = self.sym.C_Logout.?(self.session_handle);
    _ = self.sym.C_CloseSession.?(self.session_handle);
    self.session_handle = 0;

    req.redirectTo("/", null) catch return;
}

pub fn getFavicon(_: *Self, req: zap.Request) void {
    req.setContentTypeFromPath() catch return;
    req.sendBody(favicon) catch return;
}
