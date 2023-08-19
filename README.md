# Hybrid Encryption Example in Go

This is an example of implementing hybrid encryption using the Go programming language. Hybrid encryption combines symmetric and asymmetric encryption to achieve a higher level of security and efficiency in data exchange.

## Overview

The example demonstrates how to:

1. Generate a symmetric encryption key for data encryption.
2. Encrypt data using symmetric encryption.
3. Decrypt data using the recipient's private key and the decrypted symmetric key.

## Prerequisites

- Go programming language installed on your system.
- Basic understanding of symmetric and asymmetric encryption.

## Usage

1. Clone or download the source code from the repository.

2. Place the recipient's private key in a file named `recipient_private_key.pem`.

3. Open a terminal and navigate to the directory containing the code.

4. Execute the following command to run the program:

   ```bash
   go run main.go
   ```

## References

- [Go Programming Language](https://golang.org/)
- [AES Encryption in Go](https://pkg.go.dev/crypto/aes)
- [RSA Encryption in Go](https://pkg.go.dev/crypto/rsa)
- [PEM Package in Go](https://pkg.go.dev/encoding/pem)
- [Crypto Package in Go](https://pkg.go.dev/crypto)
