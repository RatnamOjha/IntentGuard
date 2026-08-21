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

& $VenvPython -c "import fastapi, uvicorn" 2>$null
if ($LASTEXITCODE -ne 0) {
    & $VenvPython -m pip install -e "$ProjectDir[api,dev]"
}

if (-not (Test-Path (Join-Path $FrontendDir "node_modules\.bin\vinext.cmd"))) {
    Push-Location $FrontendDir
    try {
        pnpm install --frozen-lockfile
    }
    finally {
        Pop-Location
    }
}

$ApiArguments = @(
    "-m", "uvicorn", "intentguard.api:app",
    "--app-dir", (Join-Path $ProjectDir "src"),
    "--host", "127.0.0.1",
    "--port", "8000",
    "--reload",
    "--reload-dir", (Join-Path $ProjectDir "src")
)
$ApiProcess = Start-Process -FilePath $VenvPython `
    -ArgumentList $ApiArguments `
    -NoNewWindow `
    -PassThru

Write-Host "IntentGuard API: http://127.0.0.1:8000"
Write-Host "IntentGuard console will use port 3000 or the next available port."

Push-Location $FrontendDir
try {
    pnpm run dev
}
finally {
    Pop-Location
    if (-not $ApiProcess.HasExited) {
        Stop-Process -Id $ApiProcess.Id
    }
}
