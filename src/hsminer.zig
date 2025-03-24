const c = @cImport({
    @cInclude("pkcs11zig.h");
});
const std = @import("std");
const zap = @import("zap");

const Mustache = zap.Mustache;
const template = @embedFile("index.mustache");

pub const HSMiner = struct {
    pub var alloc: std.mem.Allocator = undefined;

    pub var sym: *c.CK_FUNCTION_LIST = undefined;

    pub fn on_request(r: zap.Request) void {
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
            //r.setContentTypeFromPath() catch return;
            r.sendBody(s) catch return;
        }
    }
};
