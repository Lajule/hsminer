# hsminer

## Create certificats files

```
openssl req -x509 -nodes -days 365 -sha256 -newkey rsa:2048 -keyout key.pem -out cert.pem
```

## Initialize HSM

```
softhsm2-util --init-token --slot 0 --label "token 1" --so-pin 1234 --pin 1234
```

```
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --slot ${SLOT} --login --pin 1234 --keygen --key-type aes:32 --label "key 1"
zig build run -- -c cert.pem -k key.pem /usr/lib/softhsm/libsofthsm2.so ${SLOT} 1234
```
