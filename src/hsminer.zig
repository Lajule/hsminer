const C = @cImport({
    @cInclude("pkcs11zig.h");
});
const std = @import("std");
const zap = @import("zap");

const index = @embedFile("index.html");
const favicon = @embedFile("favicon.ico");

const Self = @This();

sym: *C.CK_FUNCTION_LIST,
session_handle: C.CK_SESSION_HANDLE,

pub fn init(sym: *C.CK_FUNCTION_LIST, slot_id: usize, pin: []const u8) Self {
    var args: C.CK_C_INITIALIZE_ARGS = .{ .flags = C.CKF_OS_LOCKING_OK };
    _ = sym.C_Initialize.?(&args);

    var session_handle: C.CK_SESSION_HANDLE = 0;
    _ = sym.C_OpenSession.?(@intCast(slot_id), C.CKF_RW_SESSION | C.CKF_SERIAL_SESSION, null, null, &session_handle);
    std.log.debug("session_handle: {}", .{session_handle});

    _ = sym.C_Login.?(session_handle, C.CKU_USER, std.mem.span(pin), pin.len);

    return .{
        .sym = sym,
        .session_handle = 0,
    };
}

pub fn deinit(self: *Self) void {
    _ = self.sym.C_Logout.?(self.session_handle);
    _ = self.sym.C_CloseSession.?(self.session_handle);
    self.session_handle = 0;
}

pub fn getIndex(_: *Self, req: zap.Request) void {
    req.sendBody(index) catch return;
}

pub fn getFavicon(_: *Self, req: zap.Request) void {
    req.setContentTypeFromPath() catch return;
    req.sendBody(favicon) catch return;
}
