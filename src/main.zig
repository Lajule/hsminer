const c = @cImport({
    @cInclude("pkcs11zig.h");
});
const std = @import("std");
const zap = @import("zap");
const HSMiner = @import("hsminer.zig");

fn not_found(req: zap.Request) void {
    std.log.info("not found handler", .{});
    req.sendBody("Not found") catch return;
}

fn loadModule() !*c.CK_FUNCTION_LIST {
    const path = std.mem.span(std.os.argv[1]);
    std.log.info("loading module from \"{s}\"", .{path});
    var dyn_lib = try std.DynLib.open(path);

    var getFunctionList: *const fn (**c.CK_FUNCTION_LIST) callconv(.c) c.CK_RV = undefined;
    getFunctionList = dyn_lib.lookup(@TypeOf(getFunctionList), "C_GetFunctionList") orelse return error.LookupFailed;

    var sym: *c.CK_FUNCTION_LIST = undefined;
    _ = getFunctionList(@ptrCast(&sym));

    return sym;
}

fn loadTls() !?zap.Tls {
    var tls: ?zap.Tls = null;

    if (std.os.argv.len > 2) {
        const cert = std.mem.span(std.os.argv[2]);
        const key = std.mem.span(std.os.argv[3]);
        std.log.info("loading TLS from \"{s}\" and \"{s}\"", .{ cert, key });

        tls = try zap.Tls.init(.{
            .public_certificate_file = cert,
            .private_key_file = key,
        });
    }

    return tls;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    const sym = try loadModule();
    var hsminer = try HSMiner.init(allocator, sym);
    defer hsminer.deinit();

    var router = zap.Router.init(allocator, .{
        .not_found = not_found,
    });
    defer router.deinit();

    try router.handle_func("/", &hsminer, &HSMiner.getIndex);
    try router.handle_func("/login", &hsminer, &HSMiner.postLogin);
    try router.handle_func("/logout", &hsminer, &HSMiner.postLogout);
    try router.handle_func("/favicon.ico", &hsminer, &HSMiner.getFavicon);

    const tls = try loadTls();
    defer {
        if (tls) |t| {
            t.deinit();
        }
    }

    var listener = zap.HttpListener.init(.{
        .port = 3000,
        .on_request = router.on_request_handler(),
        .log = false,
        .max_clients = 100000,
        .tls = tls,
    });
    try listener.listen();

    std.log.info("Listening on 0.0.0.0:3000", .{});

    zap.start(.{
        .threads = 2,
        .workers = 1,
    });
}
