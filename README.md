# hsminer

```
openssl req -x509 -nodes -days 365 -sha256 -newkey rsa:2048 -keyout key.pem -out cert.pem
zig build run -- -c cert.pem -k key.pem /usr/lib/softhsm/libsofthsm2.so ${SLOT} 1234
```
