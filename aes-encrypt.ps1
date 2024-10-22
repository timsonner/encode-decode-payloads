function AES-Encrypt {
    param (
        [string]$plaintext,
        [string]$key
    )

    # Convert key to 32 bytes (256-bit AES key)
    $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($key.PadRight(32, '0').Substring(0, 32))

    # Convert plaintext to byte array
    $plaintextBytes = [System.Text.Encoding]::UTF8.GetBytes($plaintext)

    # Create AES encryption object
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $keyBytes
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

    # Generate a random initialization vector (IV)
    $aes.GenerateIV()
    $iv = $aes.IV

    # Create encryptor
    $encryptor = $aes.CreateEncryptor()

    # Encrypt the data
    $encryptedBytes = $encryptor.TransformFinalBlock($plaintextBytes, 0, $plaintextBytes.Length)

    # Combine IV and encrypted bytes
    $resultBytes = $iv + $encryptedBytes

    # Convert result to base64 for easier storage and transmission
    return [Convert]::ToBase64String($resultBytes)
}
