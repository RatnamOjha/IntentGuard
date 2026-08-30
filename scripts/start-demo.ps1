$ErrorActionPreference = "Stop"

$ProjectDir = Split-Path -Parent $PSScriptRoot
$FrontendDir = Join-Path $ProjectDir "prototype"

function Resolve-VenvPython {
    param([string]$Root)
    foreach ($Candidate in @("Scripts\python.exe", "bin\python.exe", "bin\python")) {
        $Path = Join-Path $Root (Join-Path ".venv" $Candidate)
        if (Test-Path $Path) { return $Path }
    }
    return $null
}

$VenvPython = Resolve-VenvPython $ProjectDir
if (-not $VenvPython) {
    python -m venv (Join-Path $ProjectDir ".venv")
    $VenvPython = Resolve-VenvPython $ProjectDir
}
if (-not $VenvPython) {
    throw "Could not find a Python interpreter inside .venv."
}

& $VenvPython -c "import intentguard, fastapi, uvicorn" 2>$null
if ($LASTEXITCODE -ne 0) {
    & $VenvPython -m pip install -e "$ProjectDir[api,dev]"
}

if (-not (Test-Path (Join-Path $FrontendDir "node_modules\.bin\vinext.cmd"))) {
    Push-Location $FrontendDir
    try {
        corepack pnpm@11.24.0 install --frozen-lockfile
    }
    finally {
        Pop-Location
    }
}

# The local demo uses an ephemeral, loopback-only issuer. Production deployments
# should run the API directly with their real JWT/JWKS environment variables.
$JwksScript = Join-Path $ProjectDir "examples\local_jwks_server.py"
$JwksProcess = Start-Process -FilePath $VenvPython `
    -ArgumentList @("-u", $JwksScript) `
    -WindowStyle Hidden `
    -PassThru
$JwksReady = $false
for ($Attempt = 0; $Attempt -lt 50; $Attempt++) {
    try {
        Invoke-RestMethod -Uri "http://127.0.0.1:9000/.well-known/jwks.json" `
            -TimeoutSec 1 | Out-Null
        $JwksReady = $true
        break
    }
    catch {
        Start-Sleep -Milliseconds 200
    }
}
if (-not $JwksReady) {
    Stop-Process -Id $JwksProcess.Id -ErrorAction SilentlyContinue
    throw "The local JWKS server did not start within 10 seconds."
}
function New-LocalDemoToken {
    param([string]$Subject, [string]$Role)
    $Body = @{
        sub = $Subject
        roles = @($Role)
        agent_id = "agt_travel_01"
        customer_id = "demo-customer"
    } | ConvertTo-Json
    $Response = Invoke-RestMethod -Uri "http://127.0.0.1:9000/token" `
        -Method Post `
        -ContentType "application/json" `
        -Body $Body
    return $Response.access_token
}
$env:INTENTGUARD_JWT_ISSUER = "http://127.0.0.1:9000"
$env:INTENTGUARD_JWKS_URL = "http://127.0.0.1:9000/.well-known/jwks.json"
$env:INTENTGUARD_JWT_AUDIENCE = "intentguard-api"
$env:NEXT_PUBLIC_INTENTGUARD_ACCESS_TOKEN = `
    New-LocalDemoToken -Subject "local-demo-admin" -Role "admin"
$env:NEXT_PUBLIC_INTENTGUARD_AGENT_ACCESS_TOKEN = `
    New-LocalDemoToken -Subject "local-demo-agent" -Role "agent"
$env:NEXT_PUBLIC_INTENTGUARD_OPERATOR_ACCESS_TOKEN = `
    New-LocalDemoToken -Subject "local-demo-operator" -Role "operator"
$env:NEXT_PUBLIC_INTENTGUARD_REVIEWER_ACCESS_TOKEN = `
    New-LocalDemoToken -Subject "local-demo-reviewer" -Role "reviewer"
$env:INTENTGUARD_CONNECTOR_ACCESS_TOKEN = `
    New-LocalDemoToken -Subject "local-booking-connector" -Role "connector"

$ApiArguments = @(
    "-m", "uvicorn", "intentguard.api:app",
    "--app-dir", (Join-Path $ProjectDir "src"),
    "--host", "127.0.0.1",
    "--port", "8000",
    "--reload",
    "--reload-dir", (Join-Path $ProjectDir "src")
)
# Local secrets live in .env, which is gitignored. Anything already set in the
# environment wins over the file.
$EnvFile = Join-Path $ProjectDir ".env"
if (Test-Path $EnvFile) {
    $ApiArguments += @("--env-file", $EnvFile)
    Write-Host "Loading environment from .env"
}
$ApiProcess = Start-Process -FilePath $VenvPython `
    -ArgumentList $ApiArguments `
    -WindowStyle Hidden `
    -PassThru

$ApiReady = $false
for ($Attempt = 0; $Attempt -lt 50; $Attempt++) {
    try {
        Invoke-RestMethod -Uri "http://127.0.0.1:8000/health" -TimeoutSec 1 | Out-Null
        $ApiReady = $true
        break
    }
    catch { Start-Sleep -Milliseconds 200 }
}
if (-not $ApiReady) {
    Stop-Process -Id $ApiProcess.Id -ErrorAction SilentlyContinue
    throw "The IntentGuard API did not start within 10 seconds."
}
$ConnectorProcess = Start-Process -FilePath $VenvPython `
    -ArgumentList @("-m", "intentguard.booking_connector") `
    -WindowStyle Hidden `
    -PassThru

Write-Host "IntentGuard API: http://127.0.0.1:8000"
Write-Host "Protected booking connector: http://127.0.0.1:8100"
Write-Host "IntentGuard console will use port 3000 or the next available port."

Push-Location $FrontendDir
try {
    corepack pnpm@11.24.0 run dev
}
finally {
    Pop-Location
    if (-not $ApiProcess.HasExited) {
        Stop-Process -Id $ApiProcess.Id
    }
    if (-not $ConnectorProcess.HasExited) {
        Stop-Process -Id $ConnectorProcess.Id
    }
    if (-not $JwksProcess.HasExited) {
        Stop-Process -Id $JwksProcess.Id
    }
}
