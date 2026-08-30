$ErrorActionPreference = "Stop"

$Version = "1.17.0"
$ExpectedSha256 = "d319e1abca6b1683e79e4e3ddb840b098c45a9257426ba998917dac8d83b7574"
$ProjectDir = Split-Path -Parent $PSScriptRoot
$ToolDir = Join-Path $ProjectDir ".tools"
$Target = Join-Path $ToolDir "opa.exe"

New-Item -ItemType Directory -Path $ToolDir -Force | Out-Null
Invoke-WebRequest `
    -Uri "https://github.com/open-policy-agent/opa/releases/download/v$Version/opa_windows_amd64.exe" `
    -OutFile $Target
$Actual = (Get-FileHash -LiteralPath $Target -Algorithm SHA256).Hash.ToLowerInvariant()
if ($Actual -ne $ExpectedSha256) {
    Remove-Item -LiteralPath $Target -Force
    throw "OPA checksum mismatch. The downloaded binary was removed."
}
& $Target version
Write-Host "OPA $Version installed with verified SHA-256 at $Target"
