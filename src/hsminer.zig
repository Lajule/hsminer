const C = @cImport({
    @cInclude("pkcs11zig.h");
});
const std = @import("std");
const zap = @import("zap");

const index = @embedFile("index.html");
const favicon = @embedFile("favicon.ico");

const Self = @This();

allocator: std.mem.Allocator,
sym: *C.CK_FUNCTION_LIST,
session_handle: C.CK_SESSION_HANDLE,

pub fn init(allocator: std.mem.Allocator, sym: *C.CK_FUNCTION_LIST, slot_id: usize, pin: []const u8) !Self {
    var args: C.CK_C_INITIALIZE_ARGS = .{ .flags = C.CKF_OS_LOCKING_OK };
    _ = sym.C_Initialize.?(&args);

    var session_handle: C.CK_SESSION_HANDLE = 0;
    _ = sym.C_OpenSession.?(@intCast(slot_id), C.CKF_RW_SESSION | C.CKF_SERIAL_SESSION, null, null, &session_handle);
    if (session_handle == 0) return error.SessionFailed;

    const p = try allocator.dupeZ(u8, pin);
    defer allocator.free(p);

    const r = sym.C_Login.?(session_handle, C.CKU_USER, p, p.len);
    if (r != 0) return error.LoginFailed;

    return .{
        .allocator = allocator,
        .sym = sym,
        .session_handle = session_handle,
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

pub fn postEncrypt(self: *Self, req: zap.Request) void {
    req.parseBody() catch return;

    const params = req.parametersToOwnedList(self.allocator, false) catch return;
    defer params.deinit();

    for (params.items) |kv| {
        if (kv.value) |v| {
            std.log.debug("{}", .{v});

            if (std.mem.eql(u8, "id", kv.key.str)) {
                continue;
            }

            if (std.mem.eql(u8, "text", kv.key.str)) {
                continue;
            }
        }
    }

    const label = "key 1";

    const templates = self.allocator.alloc(C.CK_ATTRIBUTE, 1) catch return;
    defer self.allocator.free(templates);

    templates[0].type = C.CKA_LABEL;
    templates[0].pValue = @constCast(@ptrCast(label.ptr));
    templates[0].ulValueLen = label.len;

    const r = self.sym.C_FindObjectsInit.?(self.session_handle, templates.ptr, 1);
    std.log.debug("{any} {}", .{ templates, r });

    const objects = self.allocator.alloc(C.CK_OBJECT_HANDLE, 1) catch return;
    defer self.allocator.free(objects);

    std.log.debug("{any}", .{objects});

    var n: c_ulong = 0;
    _ = self.sym.C_FindObjects.?(self.session_handle, objects.ptr, 1, @constCast(&n));
    std.log.debug("{any} {}", .{ objects, n });

    _ = self.sym.C_FindObjectsFinal.?(self.session_handle);

    _ = self.sym.C_EncryptInit.?(self.session_handle, 0, objects[0]);
    //_ = self.sym.C_Encrypt
    //_ = self.sym.C_EncryptFinal

    req.redirectTo("/", null) catch return;
}
