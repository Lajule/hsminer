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
