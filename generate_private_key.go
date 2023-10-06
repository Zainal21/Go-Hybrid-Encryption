package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func main() {
	// Generate an RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("Error generating RSA private key:", err)
		return
	}

	// Encode the private key in PEM format
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	// Create or overwrite the PEM file
	pemFile, err := os.Create("recipient_private_key.pem")
	if err != nil {
		fmt.Println("Error creating PEM file:", err)
		return
	}
	defer pemFile.Close()

	// Write the PEM data to the file
	if err := pem.Encode(pemFile, pemBlock); err != nil {
		fmt.Println("Error writing PEM data:", err)
		return
	}

	fmt.Println("RSA private key saved to recipient_private_key.pem")
}