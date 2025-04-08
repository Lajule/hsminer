const C = @cImport({
    @cInclude("pkcs11zig.h");
});
const std = @import("std");
const zap = @import("zap");

const index = @embedFile("index.mustache");

const Self = @This();

allocator: std.mem.Allocator,
sym: *C.CK_FUNCTION_LIST,
session_handle: C.CK_SESSION_HANDLE,
template: zap.Mustache,

// Initializes a PKCS#11 session, logs in with the provided user PIN,
// and prepares a Mustache template for later use.
pub fn init(allocator: std.mem.Allocator, sym: *C.CK_FUNCTION_LIST, slot_id: usize, pin: []const u8) !Self {
    var args: C.CK_C_INITIALIZE_ARGS = .{ .flags = C.CKF_OS_LOCKING_OK };
    var r = sym.C_Initialize.?(&args);
    if (r != C.CKR_OK) {
        std.log.debug("C_Initialize failed: {}", .{r});
        return error.InitializeFailed;
    }

    var session_handle: C.CK_SESSION_HANDLE = 0;
    r = sym.C_OpenSession.?(@intCast(slot_id), C.CKF_RW_SESSION | C.CKF_SERIAL_SESSION, null, null, &session_handle);
    if (r != C.CKR_OK) {
        std.log.debug("C_OpenSession failed: {}", .{r});
        return error.OpenSessionFailed;
    }

    const p = try allocator.dupeZ(u8, pin);
    defer allocator.free(p);

    r = sym.C_Login.?(session_handle, C.CKU_USER, p, p.len);
    if (r != C.CKR_OK) {
        std.log.debug("C_Login failed: {}", .{r});
        return error.LoginFailed;
    }

    const template = try zap.Mustache.fromData(index);

    return .{
        .allocator = allocator,
        .sym = sym,
        .session_handle = session_handle,
        .template = template,
    };
}

// Cleans up the PKCS#11 session by logging out and closing the session.
pub fn deinit(self: *Self) void {
    var r = self.sym.C_Logout.?(self.session_handle);
    if (r != C.CKR_OK) std.log.debug("C_Logout failed: {}", .{r});

    r = self.sym.C_CloseSession.?(self.session_handle);
    if (r != C.CKR_OK) std.log.debug("CloseSession failed: {}", .{r});

    self.session_handle = 0;
}

pub fn getIndex(self: *Self, req: zap.Request) !void {
    try self.renderTemplate(req, .{
        .encrypt = true,
    });
}

pub fn postAction(self: *Self, req: zap.Request) !void {
    try req.parseBody();

    const function = try self.formParam(req, "function");
    const label = try self.formParam(req, "label");
    const text = try self.formParam(req, "text");

    const encrypt = std.mem.eql(u8, function, "encrypt");

    const object = try self.findKey(label);
    if (object) |o| {
        const iv = try self.allocator.alloc(u8, 16);
        defer self.allocator.free(iv);

        var mechanism: C.CK_MECHANISM = .{
            .mechanism = C.CKM_AES_CBC_PAD,
            .pParameter = &iv[0],
            .ulParameterLen = iv.len,
        };

        const result: []const u8 = if (encrypt)
            try self.encryptText(text, &mechanism, o)
        else
            try self.decryptText(text, &mechanism, o);
        defer self.allocator.free(result);

        return try self.renderTemplate(req, .{
            .encrypt = encrypt,
            .label = label,
            .text = text,
            .result = result,
        });
    }

    return try self.renderTemplate(req, .{
        .encrypt = encrypt,
        .label = label,
        .text = text,
    });
}

fn encryptText(self: *Self, text: []const u8, mechanism: *C.CK_MECHANISM, object: C.CK_OBJECT_HANDLE) ![]const u8 {
    var r = self.sym.C_EncryptInit.?(self.session_handle, mechanism, object);
    if (r != C.CKR_OK) {
        std.log.debug("C_EncryptInit failed: {}", .{r});
        return error.EncryptInitFailed;
    }

    const data = try self.allocator.dupeZ(u8, text);
    defer self.allocator.free(data);

    var buf_len: c_ulong = 0;
    r = self.sym.C_Encrypt.?(self.session_handle, data, data.len, 0, &buf_len);
    if (r != C.CKR_OK) {
        std.log.debug("C_Encrypt failed: {}", .{r});
        return error.EncryptFailed;
    }

    var buf = try self.allocator.alloc(u8, buf_len);
    defer self.allocator.free(buf);

    r = self.sym.C_Encrypt.?(self.session_handle, data, data.len, &buf[0], &buf_len);
    if (r != C.CKR_OK) {
        std.log.debug("C_Encrypt failed: {}", .{r});
        return error.EncryptFailed;
    }

    const encoded_buf = try self.allocator.alloc(u8, std.base64.standard.Encoder.calcSize(buf_len));
    return std.base64.standard.Encoder.encode(encoded_buf, buf);
}

fn decryptText(self: *Self, text: []const u8, mechanism: *C.CK_MECHANISM, object: C.CK_OBJECT_HANDLE) ![]const u8 {
    var r = self.sym.C_DecryptInit.?(self.session_handle, mechanism, object);
    if (r != C.CKR_OK) {
        std.log.debug("C_DecryptInit failed: {}", .{r});
        return error.DecryptInitFailed;
    }

    const data_len = try std.base64.standard.Decoder.calcSizeForSlice(text);
    const data = try self.allocator.alloc(u8, data_len);
    defer self.allocator.free(data);

    try std.base64.standard.Decoder.decode(data, text);

    var buf_len: c_ulong = data_len;
    // data and buf can point to the same location.
    r = self.sym.C_Decrypt.?(self.session_handle, &data[0], data_len, &data[0], &buf_len);
    if (r != C.CKR_OK) {
        std.log.debug("C_Decrypt failed: {}", .{r});
        return error.DecryptFailed;
    }

    return try self.allocator.dupe(u8, data[0..buf_len]);
}

fn formParam(self: *Self, req: zap.Request, name: []const u8) ![]const u8 {
    const param = req.getParamStr(self.allocator, name, false) catch |err| return err;
    if (param) |p| return p.str;
    return error.UnknownParam;
}

fn findKey(self: *Self, label: []const u8) !?C.CK_OBJECT_HANDLE {
    const value = try self.allocator.dupeZ(u8, label);
    defer self.allocator.free(value);

    var template: C.CK_ATTRIBUTE = .{
        .type = C.CKA_LABEL,
        .pValue = &value[0],
        .ulValueLen = value.len,
    };
    var r = self.sym.C_FindObjectsInit.?(self.session_handle, &template, 1);
    if (r != C.CKR_OK) {
        std.log.debug("C_FindObjectsInit failed: {}", .{r});
        return error.FindObjectsInitFailed;
    }

    var o: C.CK_OBJECT_HANDLE = 0;
    var n: c_ulong = 0;
    r = self.sym.C_FindObjects.?(self.session_handle, &o, 1, &n);
    if (r != C.CKR_OK) {
        std.log.debug("C_FindObjects failed: {}", .{r});
        return error.FindObjectsFailed;
    }

    r = self.sym.C_FindObjectsFinal.?(self.session_handle);
    if (r != C.CKR_OK) {
        std.log.debug("C_FindObjectsFinal failed: {}", .{r});
        return error.FindObjectsFinalFailed;
    }

    return if (n == 1) o else null;
}

fn renderTemplate(self: *Self, req: zap.Request, state: anytype) !void {
    const ret = self.template.build(state);
    defer ret.deinit();

    if (ret.str()) |s| {
        try req.setContentType(.HTML);
        try req.sendBody(s);
    }
}
