const C = @cImport({
    @cInclude("pkcs11zig.h");
});
const std = @import("std");
const zap = @import("zap");

const index = @embedFile("index.mustache");
const style = @embedFile("style.css");
const favicon = @embedFile("favicon.ico");

const Self = @This();

allocator: std.mem.Allocator,
sym: *C.CK_FUNCTION_LIST,
session_handle: C.CK_SESSION_HANDLE,
template: zap.Mustache,

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
        .template = try zap.Mustache.fromData(index),
    };
}

pub fn deinit(self: *Self) void {
    _ = self.sym.C_Logout.?(self.session_handle);
    _ = self.sym.C_CloseSession.?(self.session_handle);
    self.session_handle = 0;
}

pub fn getIndex(self: *Self, req: zap.Request) void {
    self.render(req, .{
        .method = true,
    });
}

pub fn getStyle(_: *Self, req: zap.Request) void {
    req.setContentTypeFromPath() catch return;
    req.sendBody(style) catch return;
}

pub fn getFavicon(_: *Self, req: zap.Request) void {
    req.setContentTypeFromPath() catch return;
    req.sendBody(favicon) catch return;
}

pub fn postEncrypt(self: *Self, req: zap.Request) void {
    req.parseBody() catch return;

    const methodParam = req.getParamStr(self.allocator, "method", false) catch return;
    const method = if (methodParam) |m| std.mem.eql(u8, m.str, "encrypt") else false;

    const label = req.getParamStr(self.allocator, "label", false) catch return;
    if (label) |l| {
        const object = self.find(l.str);

        if (object != 0) {
            const text = req.getParamStr(self.allocator, "text", false) catch return;
            if (text) |t| {
                const iv = self.allocator.alloc(u8, 16) catch return;
                defer self.allocator.free(iv);

                var mechanism: C.CK_MECHANISM = .{
                    .mechanism = C.CKM_AES_CBC_PAD,
                    .pParameter = &iv[0],
                    .ulParameterLen = iv.len,
                };

                if (method) {
                    _ = self.sym.C_EncryptInit.?(self.session_handle, &mechanism, object);

                    const data = self.allocator.dupeZ(u8, t.str) catch return;
                    defer self.allocator.free(data);

                    var buf: [256]u8 = undefined;
                    var buf_len: c_ulong = 256;
                    _ = self.sym.C_Encrypt.?(self.session_handle, data, data.len, &buf[0], &buf_len);

                    var result: [256]u8 = undefined;
                    const str = std.fmt.bufPrint(&result, "{s}", .{std.fmt.fmtSliceHexLower(buf[0..buf_len])}) catch return;

                    self.render(req, .{
                        .method = method,
                        .label = l.str,
                        .text = t.str,
                        .result = str,
                    });
                } else {
                    _ = self.sym.C_DecryptInit.?(self.session_handle, &mechanism, object);

                    var data: [1024]u8 = undefined;
                    const str = std.fmt.hexToBytes(&data, t.str) catch return;

                    var buf: [1024]u8 = undefined;
                    var buf_len: c_ulong = 1024;
                    _ = self.sym.C_Decrypt.?(self.session_handle, &str[0], str.len, &buf[0], &buf_len);

                    self.render(req, .{
                        .method = method,
                        .label = l.str,
                        .text = t.str,
                        .result = buf[0..buf_len],
                    });
                }
            }
        } else {
            self.render(req, .{
                .method = method,
                .label = l.str,
            });
        }
    } else {
        self.render(req, .{
            .method = method,
        });
    }
}

fn find(self: *Self, label: []const u8) C.CK_OBJECT_HANDLE {
    const value = self.allocator.dupeZ(u8, label) catch return 0;
    defer self.allocator.free(value);

    var template: C.CK_ATTRIBUTE = .{
        .type = C.CKA_LABEL,
        .pValue = &value[0],
        .ulValueLen = value.len,
    };
    _ = self.sym.C_FindObjectsInit.?(self.session_handle, &template, 1);

    var object: C.CK_OBJECT_HANDLE = 0;
    var n: c_ulong = 0;
    _ = self.sym.C_FindObjects.?(self.session_handle, &object, 1, &n);

    _ = self.sym.C_FindObjectsFinal.?(self.session_handle);

    return object;
}

fn render(self: *Self, req: zap.Request, state: anytype) void {
    const ret = self.template.build(state);
    defer ret.deinit();

    req.setContentType(.HTML) catch return;

    if (ret.str()) |s| {
        req.sendBody(s) catch return;
    }
}
