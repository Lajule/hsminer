# hsminer

```
openssl req -x509 -nodes -days 365 -sha256 -newkey rsa:2048 -keyout mykey.pem -out mycert.pem
````

```
softhsm2-util --init-token --slot 0 --label "token 1" --pin 1234
```

```
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --slot 1502799447 --login --login-type user --keygen --key-type aes:32 --label "key 1"
```

```
zig build run -- -c cert.pem -k key.pem /usr/lib/softhsm/libsofthsm2.so 1502799447 1234
```
