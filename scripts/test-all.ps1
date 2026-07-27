$ErrorActionPreference = "Stop"

$ProjectDir = Split-Path -Parent $PSScriptRoot
$FrontendDir = Join-Path $ProjectDir "prototype"
$VenvPython = Join-Path $ProjectDir ".venv\Scripts\python.exe"

if (-not (Test-Path $VenvPython)) {
    python -m venv (Join-Path $ProjectDir ".venv")
}

& $VenvPython -c "import fastapi, httpx" 2>$null
if ($LASTEXITCODE -ne 0) {
    & $VenvPython -m pip install -e "$ProjectDir[api,dev]"
}

$env:PYTHONPATH = Join-Path $ProjectDir "src"
& $VenvPython -m unittest discover -s (Join-Path $ProjectDir "tests") -v

Push-Location $FrontendDir
try {
    & ".\node_modules\.bin\vinext.cmd" build
    node --test tests/rendered-html.test.mjs
    & ".\node_modules\.bin\eslint.cmd" app lib tests
}
finally {
    Pop-Location
}
