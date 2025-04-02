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
    var r = sym.C_Initialize.?(&args);
    if (r != C.CKR_OK) return error.InitializeFailed;

    var session_handle: C.CK_SESSION_HANDLE = 0;
    r = sym.C_OpenSession.?(@intCast(slot_id), C.CKF_RW_SESSION | C.CKF_SERIAL_SESSION, null, null, &session_handle);
    if (r != C.CKR_OK) return error.OpenSessionFailed;

    const p = try allocator.dupeZ(u8, pin);
    defer allocator.free(p);

    r = sym.C_Login.?(session_handle, C.CKU_USER, p, p.len);
    if (r != C.CKR_OK) return error.LoginFailed;

    const template = try zap.Mustache.fromData(index);

    return .{
        .allocator = allocator,
        .sym = sym,
        .session_handle = session_handle,
        .template = template,
    };
}

pub fn deinit(self: *Self) void {
    var r = self.sym.C_Logout.?(self.session_handle);
    if (r != C.CKR_OK) std.log.debug("Logout failed: {}", .{r});

    r = self.sym.C_CloseSession.?(self.session_handle);
    if (r != C.CKR_OK) std.log.debug("CloseSession failed: {}", .{r});

    self.session_handle = 0;
}

pub fn getIndex(self: *Self, req: zap.Request) void {
    self.render(req, .{
        .encrypt = true,
    }) catch return;
}

pub fn getStyle(_: *Self, req: zap.Request) void {
    req.setContentTypeFromPath() catch return;
    req.sendBody(style) catch return;
}

pub fn getFavicon(_: *Self, req: zap.Request) void {
    req.setContentTypeFromPath() catch return;
    req.sendBody(favicon) catch return;
}

pub fn postAction(self: *Self, req: zap.Request) void {
    req.parseBody() catch return;

    const function = self.param(req, "function") catch return;
    const encrypt = std.mem.eql(u8, function, "encrypt");
    const decrypt = std.mem.eql(u8, function, "decrypt");

    const label = self.param(req, "label") catch return;

    const text = self.param(req, "text") catch return;

    const object = self.find(label) catch return;
    if (object != 0) {
        const iv = self.allocator.alloc(u8, 16) catch return;
        defer self.allocator.free(iv);

        var mechanism: C.CK_MECHANISM = .{
            .mechanism = C.CKM_AES_CBC_PAD,
            .pParameter = &iv[0],
            .ulParameterLen = iv.len,
        };

        if (encrypt) {
            var r = self.sym.C_EncryptInit.?(self.session_handle, &mechanism, object);
            if (r != C.CKR_OK) std.log.debug("EncryptInit failed: {}", .{r});

            const data = self.allocator.dupeZ(u8, text) catch return;
            defer self.allocator.free(data);

            var buf: [256]u8 = undefined;
            var buf_len: c_ulong = 256;
            r = self.sym.C_Encrypt.?(self.session_handle, data, data.len, &buf[0], &buf_len);
            if (r != C.CKR_OK) std.log.debug("Encrypt failed: {}", .{r});

            const formatter = std.fmt.fmtSliceHexLower(buf[0..buf_len]);
            var encoded_buf: [256]u8 = undefined;
            const encoded_str = std.fmt.bufPrint(&encoded_buf, "{s}", .{formatter}) catch return;

            self.render(req, .{
                .encrypt = encrypt,
                .label = label,
                .text = text,
                .result = encoded_str,
            }) catch return;
        }

        if (decrypt) {
            var r = self.sym.C_DecryptInit.?(self.session_handle, &mechanism, object);
            if (r != C.CKR_OK) std.log.debug("DecryptInit failed: {}", .{r});

            var data: [1024]u8 = undefined;
            const data_str = std.fmt.hexToBytes(&data, text) catch return;

            var buf: [1024]u8 = undefined;
            var buf_len: c_ulong = 1024;
            r = self.sym.C_Decrypt.?(self.session_handle, &data_str[0], data_str.len, &buf[0], &buf_len);
            if (r != C.CKR_OK) std.log.debug("Decrypt failed: {}", .{r});

            self.render(req, .{
                .decrypt = decrypt,
                .label = label,
                .text = text,
                .result = buf[0..buf_len],
            }) catch return;
        }
    } else {
        self.render(req, .{
            .encrypt = encrypt,
            .decrypt = decrypt,
            .label = label,
            .text = text,
        }) catch return;
    }
}

fn param(self: *Self, req: zap.Request, name: []const u8) ![]const u8 {
    const p = req.getParamStr(self.allocator, name, false) catch |err| {
        try req.redirectTo("/", null);
        return err;
    };

    if (p) |v| {
        return v.str;
    }

    try req.redirectTo("/", null);
    return error.UnknownParam;
}

fn find(self: *Self, label: []const u8) !C.CK_OBJECT_HANDLE {
    const value = try self.allocator.dupeZ(u8, label);
    defer self.allocator.free(value);

    var template: C.CK_ATTRIBUTE = .{
        .type = C.CKA_LABEL,
        .pValue = &value[0],
        .ulValueLen = value.len,
    };
    var r = self.sym.C_FindObjectsInit.?(self.session_handle, &template, 1);
    if (r != C.CKR_OK) return error.FindObjectsInitFailed;

    var object: C.CK_OBJECT_HANDLE = 0;
    var n: c_ulong = 0;
    r = self.sym.C_FindObjects.?(self.session_handle, &object, 1, &n);
    if (r != C.CKR_OK) return error.FindObjectsFailed;

    r = self.sym.C_FindObjectsFinal.?(self.session_handle);
    if (r != C.CKR_OK) return error.FindObjectsFinalFailed;

    return object;
}

fn render(self: *Self, req: zap.Request, state: anytype) !void {
    const ret = self.template.build(state);
    defer ret.deinit();

    if (req.setContentType(.HTML)) {
        if (ret.str()) |s| {
            try req.sendBody(s);
        } else {
            try req.redirectTo("/", null);
        }
    } else |err| {
        try req.redirectTo("/", null);
        return err;
    }
}
