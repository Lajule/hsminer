# hsminer

**hsminer** is a Zig-based project designed to interact with a Hardware Security Module (HSM) using the PKCS#11 standard. It allows you to encrypt or decrypt text using cryptographic keys.

![HSMiner](https://github.com/Lajule/hsminer/blob/main/HSMiner.png)

## Building hsminer

Use Zig to build the project:

```sh
zig build
```

## Running hsminer

Use Zig to build and run the project:

```sh
zig build run -- -c cert.pem -k key.pem /usr/lib/softhsm/libsofthsm2.so "${SLOT_ID}" "${PIN}"
```

or HSMiner binary:

```sh
./hsminer -c cert.pem -k key.pem /usr/lib/softhsm/libsofthsm2.so "${SLOT_ID}" "${PIN}"
```

### Command Arguments:

- -h, --help         Display this help and exit.
- -c, --cert <str>   Path to certificat file.
- -k, --key <str>    Path to key file.
- -p, --port <usize> Listening port.
- <str>              Path to PKCS11 module.
- <usize>            Slot identifier.
- <str>              Pin (4-255).

#### Enviroment

Make sure the following tools are installed on your system:

- **OpenSSL** – for generating self-signed certificates.
- **SoftHSM** – a software-based HSM that supports PKCS#11.
- **pkcs11-tool** – a command-line utility to interact with PKCS#11 modules.
- **Zig** – the programming language used to build and run this project.

Or build a docker image with:

```sh
docker build -t hsminer .
```

And run it with:

```sh
docker run -it --rm -p 3000:3000 -v "${PWD}":/hsminer -v "${PWD}"/tokens:/var/lib/softhsm/tokens -w /hsminer hsminer bash
```

### Generating Certificate and Key

Before running `hsminer`, generate a self-signed certificate and a private key:

```sh
openssl req -x509 -nodes -days 365 -sha256 -newkey rsa:2048 -keyout key.pem -out cert.pem
```

This creates:

- `key.pem`: the private key.
- `cert.pem`: the matching self-signed certificate.

### Initialize the Token

```sh
softhsm2-util --init-token --free --label "HSMiner" --so-pin 1234 --pin 1234
```

### Generate a Key

```bash
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --slot "${SLOT_ID}" --login --pin 1234 --keygen --key-type aes:32 --label "key 1"
```

This command creates a 256-bit AES key with the label `key 1` in the initialized slot.

## Resources

- [SoftHSM Documentation](https://www.opendnssec.org/softhsm/)
- [PKCS#11 Specification](https://www.cryptsoft.com/pkcs11doc/)
- [Zig Programming Language](https://ziglang.org/)
