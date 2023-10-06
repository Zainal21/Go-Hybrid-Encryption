package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

func main() {
	// generateRsaKey()
	// Generate a symmetric key for data encryption
	symmetricKey := make([]byte, 32)
	if _, err := rand.Read(symmetricKey); err != nil {
		fmt.Println("Error generating symmetric key:", err)
		return
	}

	// Encrypt data using symmetric encryption
	data := []byte("Hello, this is a secret message.")
	ciphertext, err := encryptWithSymmetricKey(data, symmetricKey)
	if err != nil {
		fmt.Println("Error encrypting data:", err)
		return
	}

	// Recipient's side
	// Load recipient's private key from PEM file
	privateKeyBytes, err := ioutil.ReadFile("recipient_private_key.pem")
	if err != nil {
		fmt.Println("Error reading private key:", err)
		return
	}
	privateKey, err := parseRSAPrivateKey(privateKeyBytes)
	if err != nil {
		fmt.Println("Error parsing private key:", err)
		return
	}

	// Decrypt the symmetric key using the recipient's private key
	decryptedSymmetricKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, symmetricKey, nil)
	if err != nil {
		fmt.Println("Error decrypting symmetric key:", err)
		return
	}

	// Decrypt data using the decrypted symmetric key
	decryptedData, err := decryptWithSymmetricKey(ciphertext, decryptedSymmetricKey)
	if err != nil {
		fmt.Println("Error decrypting data:", err)
		return
	}

	fmt.Println("Decrypted data:", string(decryptedData))
}

func encryptWithSymmetricKey(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], data)

	return ciphertext, nil
}

func decryptWithSymmetricKey(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return ciphertext, nil
}

func parseRSAPrivateKey(keyData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}
