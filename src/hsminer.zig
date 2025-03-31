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

    const label = req.getParamStr(self.allocator, "label", false) catch return;
    if (label) |l| {
        const value = self.allocator.dupeZ(u8, l.str) catch return;
        defer self.allocator.free(value);

        var templates: [1]C.CK_ATTRIBUTE = .{
            .{
                .type = C.CKA_LABEL,
                .pValue = @ptrCast(value),
                .ulValueLen = value.len,
            },
        };
        _ = self.sym.C_FindObjectsInit.?(self.session_handle, &templates, 1);

        var objects: [1]C.CK_OBJECT_HANDLE = .{0};
        var n: c_ulong = 0;
        _ = self.sym.C_FindObjects.?(self.session_handle, &objects, 1, &n);

        _ = self.sym.C_FindObjectsFinal.?(self.session_handle);

        if (n == 1) {
            std.log.info("found key with label {s}", .{value});

            const text = req.getParamStr(self.allocator, "text", false) catch return;
            if (text) |t| {
                const data = self.allocator.dupeZ(u8, t.str) catch return;
                defer self.allocator.free(data);

                var iv = self.allocator.alloc(u8, 16) catch return;
                defer self.allocator.free(iv);

                var mechanism: C.CK_MECHANISM = .{
                    .mechanism = C.CKM_AES_CBC_PAD,
                    .pParameter = &iv[0],
                    .ulParameterLen = 16 * @sizeOf(u8),
                };
                var r = self.sym.C_EncryptInit.?(self.session_handle, &mechanism, objects[0]);
                std.log.debug("{any}", .{r});

                var encrypted_data = self.allocator.alloc(u8, 2048) catch return;
                defer self.allocator.free(encrypted_data);

                var encrypted_data_len: c_ulong = 2028 * @sizeOf(u8);
                r = self.sym.C_Encrypt.?(self.session_handle, data, data.len, &encrypted_data[0], &encrypted_data_len);
                std.log.debug("{any}", .{r});

                std.log.debug("{any}", .{encrypted_data_len});

                _ = self.sym.C_EncryptFinal.?(self.session_handle, &encrypted_data[0], encrypted_data_len);
                std.log.debug("\"{s}\" {any} {any}", .{ encrypted_data, encrypted_data_len, r });
            }
        }
    }

    req.redirectTo("/", null) catch return;
}
