const C = @cImport({
    @cInclude("pkcs11zig.h");
});
const std = @import("std");
const clap = @import("clap");
const zap = @import("zap");

const HSMiner = @import("hsminer.zig");

// Loads a PKCS#11 module from a dynamic library and retrieves its function list.
fn loadModule(module: []const u8) !*C.CK_FUNCTION_LIST {
    std.log.info("loading module from \"{s}\"", .{module});
    var dyn_lib = try std.DynLib.open(module);

    var get_function_list: *const fn (**C.CK_FUNCTION_LIST) callconv(.c) C.CK_RV = undefined;
    get_function_list = dyn_lib.lookup(@TypeOf(get_function_list), "C_GetFunctionList") orelse return error.LookupFailed;

    var sym: *C.CK_FUNCTION_LIST = undefined;
    const r = get_function_list(@ptrCast(&sym));
    if (r != C.CKR_OK) return error.GetFunctionListFailed;

    return sym;
}

// Loads TLS configuration using the provided certificate and key paths.
fn loadTls(allocator: std.mem.Allocator, cert: ?[]const u8, key: ?[]const u8) !?zap.Tls {
    var tls: ?zap.Tls = null;

    if (cert) |c| {
        if (key) |k| {
            std.log.info("loading TLS from \"{s}\" and \"{s}\"", .{ c, k });

            const public_certificate_file = try allocator.dupeZ(u8, c);
            defer allocator.free(public_certificate_file);

            const private_key_file = try allocator.dupeZ(u8, k);
            defer allocator.free(private_key_file);

            tls = try zap.Tls.init(.{
                .public_certificate_file = public_certificate_file,
                .private_key_file = private_key_file,
            });
        }
    }

    return tls;
}

fn notFound(req: zap.Request) void {
    std.log.info("not found handler", .{});
    req.sendBody("Not found") catch return;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const allocator = gpa.allocator();

    const params = comptime clap.parseParamsComptime(
        \\-h, --help         Display this help and exit.
        \\-c, --cert <str>   Path to certificat file.
        \\-k, --key <str>    Path to key file.
        \\-p, --port <usize> Listening port.
        \\<str>              Path to PKCS11 module.
        \\<usize>            Slot identifier.
        \\<str>              Pin (4-255).
        \\
    );

    var res = try clap.parse(clap.Help, &params, clap.parsers.default, .{
        .allocator = allocator,
    });
    defer res.deinit();

    if (res.args.help != 0) {
        return clap.help(std.io.getStdErr().writer(), clap.Help, &params, .{});
    }

    const module = res.positionals[0] orelse return clap.usage(std.io.getStdErr().writer(), clap.Help, &params);
    const slot_id = res.positionals[1] orelse return clap.usage(std.io.getStdErr().writer(), clap.Help, &params);
    const pin = res.positionals[2] orelse return clap.usage(std.io.getStdErr().writer(), clap.Help, &params);

    const sym = try loadModule(module);
    var hsminer = try HSMiner.init(allocator, sym, slot_id, pin);
    defer hsminer.deinit();

    var router = zap.Router.init(allocator, .{
        .not_found = notFound,
    });
    defer router.deinit();

    try router.handle_func("/", &hsminer, &HSMiner.getIndex);
    try router.handle_func("/action", &hsminer, &HSMiner.postAction);

    const tls = try loadTls(allocator, res.args.cert, res.args.key);
    defer {
        if (tls) |t| {
            t.deinit();
        }
    }

    var listener = zap.HttpListener.init(.{
        .port = res.args.port orelse 3000,
        .on_request = router.on_request_handler(),
        .log = true,
        .tls = tls,
    });
    try listener.listen();

    std.log.info("listening on 0.0.0.0:3000", .{});

    zap.start(.{
        .threads = 2,
        .workers = 1,
    });
}
