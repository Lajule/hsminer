# hsminer

```
openssl req -x509 -nodes -days 365 -sha256 -newkey rsa:2048 -keyout mykey.pem -out mycert.pem
````

```
softhsm2-util --init-token --slot 0 --label "My token 1" --pin 1234
```

```
zig build run -- /usr/lib/softhsm/libsofthsm2.so ./mycert.pem ./mykey.pem
```

```
    ...
    var handle: c.CK_SESSION_HANDLE = 0;
    var r = HSMiner.sym.C_OpenSession.?(slot_list[0], c.CKF_RW_SESSION | c.CKF_SERIAL_SESSION, null, null, &handle);
    std.debug.print("session {} {}\n", .{ r == c.CKR_TOKEN_NOT_RECOGNIZED, handle });

    r = HSMiner.sym.C_Login.?(handle, c.CKU_USER, @constCast("1234".ptr), 4);
    std.debug.print("login {}\n", .{r});
    ...
```