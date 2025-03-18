const c = @cImport({
    @cDefine("CK_PTR", "*");
    @cDefine("CK_DEFINE_FUNCTION(returnType, name)", "returnType name");
    @cDefine("CK_DECLARE_FUNCTION(returnType, name)", "returnType name");
    @cDefine("CK_DECLARE_FUNCTION_POINTER(returnType, name)", "returnType (* name)");
    @cDefine("CK_CALLBACK_FUNCTION(returnType, name)", "returnType (* name)");
    @cInclude("pkcs11.h");
});
const std = @import("std");

var getFunctionList: *const fn (**c.CK_FUNCTION_LIST) callconv(.c) c.CK_RV = undefined;

var sym: *c.CK_FUNCTION_LIST = undefined;

pub fn main() anyerror!void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    const dll_path = "/usr/lib/softhsm/libsofthsm2.so";

    std.debug.print("loading dll from \"{s}\"\n", .{dll_path});
    var dyn_lib = std.DynLib.open(dll_path) catch {
        return error.OpenFail;
    };

    getFunctionList = dyn_lib.lookup(
        @TypeOf(getFunctionList),
        "C_GetFunctionList",
    ) orelse return error.LookupFailed;

    _ = getFunctionList(@ptrCast(&sym));
    std.debug.print("sym \"{}\"\n", .{sym});

    var args: c.CK_C_INITIALIZE_ARGS = .{ .flags = c.CKF_OS_LOCKING_OK };
    _ = sym.C_Initialize.?(&args);

    var info: c.CK_INFO = undefined;
    _ = sym.C_GetInfo.?(&info);
    const manufacturer_id: [32]u8 = info.manufacturerID;
    std.debug.print("info \"{s}\"\n", .{manufacturer_id});

    const present: c.CK_BBOOL = c.CK_TRUE;
    var slot_count: c.CK_ULONG = undefined;
    _ = sym.C_GetSlotList.?(present, null, &slot_count);
    std.debug.print("slot_count \"{}\"\n", .{slot_count});

    const slot_list = try allocator.alloc(c.CK_ULONG, slot_count);
    errdefer allocator.free(slot_list);

    _ = sym.C_GetSlotList.?(present, slot_list.ptr, &slot_count);
    var slot_info: c.CK_SLOT_INFO = undefined;
    _ = sym.C_GetSlotInfo.?(slot_list[0], &slot_info);
    const slot_description: [64]u8 = slot_info.slotDescription;
    std.debug.print("slot_info \"{s}\"\n", .{slot_description});
}
