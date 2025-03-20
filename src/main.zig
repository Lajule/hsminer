const c = @cImport({
    @cInclude("pkcs11zig.h");
});
const std = @import("std");
const Mustache = @import("zap").Mustache;

var getFunctionList: *const fn (**c.CK_FUNCTION_LIST) callconv(.c) c.CK_RV = undefined;

var sym: *c.CK_FUNCTION_LIST = undefined;

pub fn main() anyerror!void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    const dll_path = std.mem.span(std.os.argv[1]);

    std.debug.print("loading dll from \"{s}\"\n", .{dll_path});
    var dyn_lib = std.DynLib.open(dll_path) catch {
        return error.OpenFail;
    };

    getFunctionList = dyn_lib.lookup(
        @TypeOf(getFunctionList),
        "C_GetFunctionList",
    ) orelse return error.LookupFailed;

    _ = getFunctionList(@ptrCast(&sym));

    var args: c.CK_C_INITIALIZE_ARGS = .{ .flags = c.CKF_OS_LOCKING_OK };
    _ = sym.C_Initialize.?(&args);

    var info: c.CK_INFO = undefined;
    _ = sym.C_GetInfo.?(&info);
    const manufacturer_id: [32]u8 = info.manufacturerID;
    std.debug.print("info \"{s}\"\n", .{manufacturer_id});

    const present: c.CK_BBOOL = c.CK_TRUE;
    var slot_count: c.CK_ULONG = undefined;
    _ = sym.C_GetSlotList.?(present, null, &slot_count);
    std.debug.print("slot_count {}\n", .{slot_count});

    const slot_list = try allocator.alloc(c.CK_ULONG, slot_count);
    errdefer allocator.free(slot_list);
    _ = sym.C_GetSlotList.?(present, slot_list.ptr, &slot_count);

    var slot_info: c.CK_SLOT_INFO = undefined;
    for (slot_list) |slot| {
        _ = sym.C_GetSlotInfo.?(slot, &slot_info);
        const slot_description: [64]u8 = slot_info.slotDescription;
        std.debug.print("slot_info {} \"{s}\"\n", .{ slot, slot_description });

        var token_info: c.CK_TOKEN_INFO = undefined;
        _ = sym.C_GetTokenInfo.?(slot, &token_info);
        const label: [32]u8 = token_info.label;
        const model: [16]u8 = token_info.model;
        std.debug.print("token \"{s}\" \"{s}\"\n", .{ label, model });
    }

    var handle: c.CK_SESSION_HANDLE = 0;
    const r = sym.C_OpenSession.?(slot_list[0], c.CKF_RW_SESSION | c.CKF_SERIAL_SESSION, null, null, &handle);
    std.debug.print("session {} {}\n", .{ r, handle });

    const template =
        \\ {{=<< >>=}}
        \\ * Users:
        \\ <<#users>>
        \\ <<id>>. <<& name>> (<<name>>)
        \\ <</users>>
        \\ Nested: <<& nested.item >>.
    ;

    var mustache = Mustache.fromData(template) catch return;
    defer mustache.deinit();

    const User = struct {
        name: []const u8,
        id: isize,
    };

    const ret = mustache.build(.{
        .users = [_]User{
            .{
                .name = "Rene",
                .id = 1,
            },
            .{
                .name = "Caro",
                .id = 6,
            },
        },
        .nested = .{
            .item = "nesting works",
        },
    });
    defer ret.deinit();

    if (ret.str()) |s| {
        std.debug.print("\"{s}\"\n", .{s});
    }
}
