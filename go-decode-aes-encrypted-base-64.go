package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
)

func main() {
	// Key for AES decryption (must match the encryption key)
	key := []byte("supersecretkey123456789012345678") // 32 bytes key for AES-256

	// Base64 encoded encrypted message
	encryptedBase64 := "spsRpHraFuNBld2beFxxx/yGrFtr2qANpO6ErU1OO1wp4L2G/F6b7q1uq2tE6T7adA7BoNVXOfBPcP70S8CGmIsNNeYZ73J8y2LkQu6NKFbf75wzuz2h5VqId0/SSnwQyVxNuUUt+ELu7YtHRSMm6VFBu7uxVF+1YDHo1yZ70cMBtTy2FRT5ikELWPCKlprJTNItoBqzM8Eoy6pGJnCKQ1Qo0HEwnu5Vh6TlFa+Xvc0MgT8y6Peycli1/PDBzVSZzVktQXA6SJLgX+1SONc6gHQEPUFg8gY4vSCV9pPz4T9nKUTBQA0cEPvRBO/0fjuNWEZ0nCOD3UA4d5AFMmT9lg=="

	// Decrypt the message
	encryptedBytes, _ := base64.StdEncoding.DecodeString(encryptedBase64)
	decrypted, err := aesDecrypt(encryptedBytes, key)
	if err != nil {
		fmt.Println("Error decrypting:", err)
		return
	}

	// Output the decrypted message
	fmt.Println("Decrypted Message:", string(decrypted))
}

// aesDecrypt decrypts ciphertext using AES in CBC mode with PKCS7 unpadding
func aesDecrypt(ciphertext []byte, key []byte) ([]byte, error) {
	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// The IV is the first blockSize bytes of the ciphertext
	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// Decrypt the message using AES in CBC mode
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	// Remove padding (PKCS7 unpadding)
	paddingLength := int(ciphertext[len(ciphertext)-1])
	return ciphertext[:len(ciphertext)-paddingLength], nil
}
