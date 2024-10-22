function AES-Decrypt {
    param (
        [string]$encryptedBase64,
        [string]$key
    )

    # Convert key to 32 bytes (256-bit AES key)
    $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($key.PadRight(32, '0').Substring(0, 32))

    # Convert base64 string back to byte array
    $encryptedBytesWithIV = [Convert]::FromBase64String($encryptedBase64)

    # Extract IV (first 16 bytes) and the actual encrypted data
    $iv = $encryptedBytesWithIV[0..15]
    $encryptedBytes = $encryptedBytesWithIV[16..($encryptedBytesWithIV.Length - 1)]

    # Create AES decryption object
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $keyBytes
    $aes.IV = $iv
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

    # Create decryptor
    $decryptor = $aes.CreateDecryptor()

    # Decrypt the data
    $decryptedBytes = $decryptor.TransformFinalBlock($encryptedBytes, 0, $encryptedBytes.Length)

    # Convert decrypted byte array to string
    return [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
}
