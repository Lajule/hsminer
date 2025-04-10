# hsminer

**hsminer** is a Zig-based project designed to interact with a Hardware Security Module (HSM) using the PKCS#11 standard. It allows you to encrypt or decrypt text using cryptographic keys.

![HSMiner](https://github.com/Lajule/hsminer/blob/main/HSMiner.png)

## Building hsminer

Use Zig to build the project:

```bash
zig build
```

## Running hsminer

Use Zig to build and run the project:

```bash
zig build run -- -c cert.pem -k key.pem /usr/lib/softhsm/libsofthsm2.so "${SLOT_ID}" 1234
```

### Command Arguments:

- `-c cert.pem`: path to the certificate file.
- `-k key.pem`: path to the private key file.
- `/usr/lib/softhsm/libsofthsm2.so`: path to the PKCS#11 shared library.
- `0`: slot ID.
- `1234`: user PIN for the token.



## Prerequisites

Make sure the following tools are installed on your system:

- **OpenSSL** – for generating self-signed certificates.
- **SoftHSM** – a software-based HSM that supports PKCS#11.
- **pkcs11-tool** – a command-line utility to interact with PKCS#11 modules.
- **Zig** – the programming language used to build and run this project.

### Installation Links

- [OpenSSL](https://www.openssl.org/)
- [SoftHSM](https://www.opendnssec.org/softhsm/)
- [OpenSC (pkcs11-tool)](https://github.com/OpenSC/OpenSC/wiki)
- [Zig Language](https://ziglang.org/download/)

## Generating Certificate and Key

Before running `hsminer`, generate a self-signed certificate and a private key:

```bash
openssl req -x509 -nodes -days 365 -sha256 -newkey rsa:2048 -keyout key.pem -out cert.pem
```

This creates:

- `key.pem`: the private key.
- `cert.pem`: the matching self-signed certificate.

## Initializing the HSM (SoftHSM)

Use SoftHSM to initialize a token and generate an AES key.

### Step 1 – Initialize the Token

```sh
softhsm2-util --init-token --free --label "HSMiner" --so-pin 1234 --pin 1234
```

### Step 2 – Generate a Key

```bash
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --slot "${SLOT_ID}" --login --pin 1234 --keygen --key-type aes:32 --label "key 1"
```

This command creates a 256-bit AES key with the label `key 1` in the initialized slot.


## Notes

- Make sure paths to certificates and PKCS#11 module are valid for your OS and setup.
- Replace PINs and labels with secure values in production environments.
- This project is intended for demonstration or prototyping purposes — always review security best practices when handling cryptographic operations.

## Resources

- [SoftHSM Documentation](https://www.opendnssec.org/softhsm/)
- [PKCS#11 Specification](https://www.cryptsoft.com/pkcs11doc/)
- [Zig Programming Language](https://ziglang.org/)
