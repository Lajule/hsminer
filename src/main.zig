const c = @cImport({
    @cInclude("pkcs11zig.h");
});
const std = @import("std");
const zap = @import("zap");
const HSMiner = @import("hsminer.zig").HSMiner;

pub fn main() anyerror!void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    HSMiner.alloc = allocator;

    const dll_path = std.mem.span(std.os.argv[1]);
    std.debug.print("loading dll from \"{s}\"\n", .{dll_path});

    var dyn_lib = std.DynLib.open(dll_path) catch {
        return error.OpenFail;
    };

    var getFunctionList: *const fn (**c.CK_FUNCTION_LIST) callconv(.c) c.CK_RV = undefined;
    getFunctionList = dyn_lib.lookup(@TypeOf(getFunctionList), "C_GetFunctionList") orelse return error.LookupFailed;
    _ = getFunctionList(@ptrCast(&HSMiner.sym));

    var args: c.CK_C_INITIALIZE_ARGS = .{ .flags = c.CKF_OS_LOCKING_OK };
    _ = HSMiner.sym.C_Initialize.?(&args);

    var info: c.CK_INFO = undefined;
    _ = HSMiner.sym.C_GetInfo.?(&info);
    const manufacturer_id: [32]u8 = info.manufacturerID;
    std.debug.print("info \"{s}\"\n", .{manufacturer_id});

    const present: c.CK_BBOOL = c.CK_TRUE;
    var slot_count: c.CK_ULONG = undefined;
    _ = HSMiner.sym.C_GetSlotList.?(present, null, &slot_count);
    std.debug.print("slot_count {}\n", .{slot_count});

    const slot_list = try allocator.alloc(c.CK_ULONG, slot_count);
    errdefer allocator.free(slot_list);
    _ = HSMiner.sym.C_GetSlotList.?(present, slot_list.ptr, &slot_count);

    var slot_info: c.CK_SLOT_INFO = undefined;
    for (slot_list) |slot| {
        _ = HSMiner.sym.C_GetSlotInfo.?(slot, &slot_info);
        const slot_description: [64]u8 = slot_info.slotDescription;
        std.debug.print("slot_info {} \"{s}\"\n", .{ slot, slot_description });

        var token_info: c.CK_TOKEN_INFO = undefined;
        _ = HSMiner.sym.C_GetTokenInfo.?(slot, &token_info);
        const label: [32]u8 = token_info.label;
        const model: [16]u8 = token_info.model;
        std.debug.print("token {} \"{s}\" \"{s}\"\n", .{ (token_info.flags & c.CKF_TOKEN_INITIALIZED) == c.CKF_TOKEN_INITIALIZED, label, model });
    }

    var handle: c.CK_SESSION_HANDLE = 0;
    var r = HSMiner.sym.C_OpenSession.?(slot_list[0], c.CKF_RW_SESSION | c.CKF_SERIAL_SESSION, null, null, &handle);
    std.debug.print("session {} {}\n", .{ r == c.CKR_TOKEN_NOT_RECOGNIZED, handle });

    r = HSMiner.sym.C_Login.?(handle, c.CKU_USER, @constCast("1234".ptr), 4);
    std.debug.print("login {}\n", .{r});

    var listener = zap.HttpListener.init(.{
        .port = 3000,
        .on_request = HSMiner.on_request,
        .log = false,
    });
    try listener.listen();

    std.debug.print("Listening on 0.0.0.0:3000\n", .{});

    // start worker threads
    zap.start(.{
        .threads = 2,
        .workers = 1,
    });
}
