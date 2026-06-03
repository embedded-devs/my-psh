param(
    [Parameter(Mandatory=$false)]
    [string]$Challenge
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$KeyFile = Join-Path $ScriptDir "private_key.pem"
$KeyPass = "000000"

if (-not $Challenge) {
    Write-Host "usage: .\unlock.ps1 <Base64Challenge>"
    Write-Host ""
    Write-Host "example:"
    Write-Host "  .\unlock.ps1 'a3f8B...Base64Challenge...=='"
    Write-Host ""
    Write-Host "Decrypt Base64 challenge and derive 8-char short key"
    Write-Host "  key file: $KeyFile"
    Write-Host "  key pass: $KeyPass"
    exit 1
}

if (-not (Test-Path $KeyFile)) {
    Write-Host "error: key file not found: $KeyFile"
    Write-Host "run gen_keys.ps1 first"
    exit 1
}

$TmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $TmpDir -Force | Out-Null

try {
    Write-Host "============================================"
    Write-Host "  Challenge Decrypt"
    Write-Host "============================================"
    Write-Host ""

    Write-Host "[1/3] RSA-OAEP decrypt..."

    $challengeBytes = [Convert]::FromBase64String($Challenge)
    if ($challengeBytes.Length -le 1) {
        Write-Host "error: challenge data too short"
        exit 1
    }
    $cipherBytes = $challengeBytes[1..($challengeBytes.Length - 1)]

    $rFile = Join-Path $TmpDir "R.bin"
    $cipherFile = Join-Path $TmpDir "cipher.bin"
    [System.IO.File]::WriteAllBytes($cipherFile, $cipherBytes)

    $opensslArgs = @(
        "pkeyutl", "-decrypt",
        "-inkey", $KeyFile,
        "-passin", "pass:$KeyPass",
        "-pkeyopt", "rsa_padding_mode:oaep",
        "-pkeyopt", "rsa_oaep_md:sha256",
        "-in", $cipherFile,
        "-out", $rFile
    )

    $null = & openssl $opensslArgs 2>&1

    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $rFile) -or (Get-Item $rFile).Length -eq 0) {
        Write-Host "error: RSA decrypt failed"
        Write-Host "  - verify challenge is correct"
        Write-Host "  - verify key file matches device public key"
        exit 1
    }

    [byte[]]$rBytes = [System.IO.File]::ReadAllBytes($rFile)
    $rSize = $rBytes.Length
    $rHex = ($rBytes | ForEach-Object { $_.ToString("x2") }) -join ""
    Write-Host "  R (${rSize} bytes): $rHex"

    Write-Host "[2/3] HMAC-SHA256 derive short key..."

    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = $rBytes
    $hmacData = [System.Text.Encoding]::UTF8.GetBytes("SHELL-UNLOCK")
    [byte[]]$hmacResult = $hmac.ComputeHash($hmacData)
    $hmac.Dispose()

    $shortKey = [Convert]::ToBase64String($hmacResult[0..5])

    Write-Host ""
    Write-Host "============================================"
    Write-Host "  Result"
    Write-Host "============================================"
    Write-Host ""
    Write-Host "  short key: $shortKey"
    Write-Host ""
    Write-Host "Enter this short key on the device to unlock"

} finally {
    if (Test-Path $TmpDir) {
        Remove-Item -Recurse -Force $TmpDir -ErrorAction SilentlyContinue
    }
}
