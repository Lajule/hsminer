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

pub fn deinit(self: *Self) void {
    var r = self.sym.C_Logout.?(self.session_handle);
    if (r != C.CKR_OK) std.log.debug("Logout failed: {}", .{r});

    r = self.sym.C_CloseSession.?(self.session_handle);
    if (r != C.CKR_OK) std.log.debug("CloseSession failed: {}", .{r});

    self.session_handle = 0;
}

pub fn getIndex(self: *Self, req: zap.Request) void {
    self.renderTemplate(req, .{
        .encrypt = true,
    }) catch return;
}

pub fn postAction(self: *Self, req: zap.Request) void {
    req.parseBody() catch return;

    const function = self.formParam(req, "function") catch return;
    const label = self.formParam(req, "label") catch return;
    const text = self.formParam(req, "text") catch return;

    const encrypt = std.mem.eql(u8, function, "encrypt");

    if (label.len > 0 and text.len > 0) {
        const object = self.findKey(label) catch return;
        if (object) |o| {
            const iv = self.allocator.alloc(u8, 16) catch return;
            defer self.allocator.free(iv);

            var mechanism: C.CK_MECHANISM = .{
                .mechanism = C.CKM_AES_CBC_PAD,
                .pParameter = &iv[0],
                .ulParameterLen = iv.len,
            };

            var result: []const u8 = undefined;

            if (encrypt) {
                result = self.encryptText(text, &mechanism, o) catch return;
            } else {
                result = self.decryptText(text, &mechanism, o) catch return;
            }

            defer self.allocator.free(result);

            self.renderTemplate(req, .{
                .encrypt = encrypt,
                .label = label,
                .text = text,
                .result = result,
            }) catch return;

            return;
        }
    }

    self.renderTemplate(req, .{
        .encrypt = encrypt,
        .label = label,
        .text = text,
    }) catch return;
}

fn encryptText(self: *Self, text: []const u8, mechanism: *C.CK_MECHANISM, object: C.CK_OBJECT_HANDLE) ![]const u8 {
    var r = self.sym.C_EncryptInit.?(self.session_handle, mechanism, object);
    if (r != C.CKR_OK) {
        std.log.debug("C_EncryptInit failed: {}", .{r});
        return error.EncryptInitFailed;
    }

    const data = try self.allocator.dupeZ(u8, text);
    defer self.allocator.free(data);

    var buf_len: c_ulong = data.len * 2;
    var buf = try self.allocator.alloc(u8, buf_len);
    defer self.allocator.free(buf);

    r = self.sym.C_Encrypt.?(self.session_handle, data, data.len, &buf[0], &buf_len);
    if (r != C.CKR_OK) {
        std.log.debug("C_Encrypt failed: {}", .{r});
        return error.EncryptFailed;
    }

    const encoded_buf = try self.allocator.alloc(u8, buf_len * 2);

    const formatter = std.fmt.fmtSliceHexLower(buf[0..buf_len]);
    return try std.fmt.bufPrint(encoded_buf, "{s}", .{formatter});
}

fn decryptText(self: *Self, text: []const u8, mechanism: *C.CK_MECHANISM, object: C.CK_OBJECT_HANDLE) ![]const u8 {
    var r = self.sym.C_DecryptInit.?(self.session_handle, mechanism, object);
    if (r != C.CKR_OK) {
        std.log.debug("C_DecryptInit failed: {}", .{r});
        return error.DecryptInitFailed;
    }

    const data = try self.allocator.alloc(u8, text.len);
    defer self.allocator.free(data);

    const data_str = try std.fmt.hexToBytes(data, text);

    var buf = try self.allocator.alloc(u8, data_str.len);
    defer self.allocator.free(buf);

    var buf_len: c_ulong = data_str.len;
    r = self.sym.C_Decrypt.?(self.session_handle, &data_str[0], data_str.len, &buf[0], &buf_len);
    if (r != C.CKR_OK) {
        std.log.debug("C_Decrypt failed: {}", .{r});
        return error.DecryptFailed;
    }

    return try self.allocator.dupe(u8, buf[0..buf_len]);
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

    if (req.setContentType(.HTML)) {
        if (ret.str()) |s| {
            try req.sendBody(s);
        }
    } else |err| {
        return err;
    }
}
