const c = @cImport({
    @cInclude("pkcs11zig.h");
});
const std = @import("std");
const zap = @import("zap");
const HSMiner = @import("hsminer.zig");

fn not_found(req: zap.Request) void {
    std.debug.print("not found handler\n", .{});
    req.sendBody("Not found") catch return;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    var router = zap.Router.init(allocator, .{
        .not_found = not_found,
    });
    defer router.deinit();

    const dll_path = std.mem.span(std.os.argv[1]);
    std.debug.print("loading dll from \"{s}\"\n", .{dll_path});
    var dyn_lib = try std.DynLib.open(dll_path);

    var getFunctionList: *const fn (**c.CK_FUNCTION_LIST) callconv(.c) c.CK_RV = undefined;
    getFunctionList = dyn_lib.lookup(@TypeOf(getFunctionList), "C_GetFunctionList") orelse return error.LookupFailed;
    var sym: *c.CK_FUNCTION_LIST = undefined;
    _ = getFunctionList(@ptrCast(&sym));

    var hsminer = try HSMiner.init(allocator, sym);
    defer hsminer.deinit();

    try router.handle_func("/", &hsminer, &HSMiner.getIndex);
    try router.handle_func("/favicon.ico", &hsminer, &HSMiner.getFavicon);
    try router.handle_func("/script.js", &hsminer, &HSMiner.getScript);
    try router.handle_func("/style.css", &hsminer, &HSMiner.getStyle);

    //const tls = try zap.Tls.init(.{
    //    .server_name = "localhost:4443",
    //    .public_certificate_file = CERT_FILE,
    //    .private_key_file = KEY_FILE,
    //});
    //defer tls.deinit();

    var listener = zap.HttpListener.init(.{
        .port = 3000,
        .on_request = router.on_request_handler(),
        .log = false,
        .max_clients = 100000,
        //.tls = tls,
    });
    try listener.listen();

    std.debug.print("Listening on 0.0.0.0:3000\n", .{});

    zap.start(.{
        .threads = 2,
        .workers = 1,
    });
}
