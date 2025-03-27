const C = @cImport({
    @cInclude("pkcs11zig.h");
});
const std = @import("std");
const clap = @import("clap");
const zap = @import("zap");
const HSMiner = @import("hsminer.zig");

fn loadModule(path: []const u8) !*C.CK_FUNCTION_LIST {
    std.log.info("loading module from \"{s}\"", .{path});
    var dyn_lib = try std.DynLib.open(path);

    var getFunctionList: *const fn (**C.CK_FUNCTION_LIST) callconv(.c) C.CK_RV = undefined;
    getFunctionList = dyn_lib.lookup(@TypeOf(getFunctionList), "C_GetFunctionList") orelse return error.LookupFailed;

    var sym: *C.CK_FUNCTION_LIST = undefined;
    _ = getFunctionList(@ptrCast(&sym));

    return sym;
}

fn loadTls(cert: ?[]const u8, key: ?[]const u8) !?zap.Tls {
    var tls: ?zap.Tls = null;

    if (cert) |c| {
        if (key) |k| {
            std.log.info("loading TLS from \"{s}\" and \"{s}\"", .{ c, k });

            tls = try zap.Tls.init(.{
                .public_certificate_file = c.ptr,
                .private_key_file = k.ptr,
            });
        }
    }

    return tls;
}

fn not_found(req: zap.Request) void {
    std.log.info("not found handler", .{});
    req.sendBody("Not found") catch return;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const allocator = gpa.allocator();

    const params = comptime clap.parseParamsComptime(
        \\-h, --help        Display this help and exit.
        \\-c, --cert <str>  Path to certificat file.
        \\-k, --key <str>   Path to key file.
        \\<str>
        \\<usize>
        \\<str>
        \\
    );

    var res = try clap.parse(clap.Help, &params, clap.parsers.default, .{
        .allocator = allocator,
    });
    defer res.deinit();

    if (res.args.help != 0) return;

    var router = zap.Router.init(allocator, .{
        .not_found = not_found,
    });
    defer router.deinit();

    var hsminer = HSMiner.init(try loadModule(res.positionals[0].?), res.positionals[1].?, res.positionals[2].?);
    try router.handle_func("/", &hsminer, &HSMiner.getIndex);
    try router.handle_func("/favicon.ico", &hsminer, &HSMiner.getFavicon);

    const tls = try loadTls(res.args.cert, res.args.key);
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
