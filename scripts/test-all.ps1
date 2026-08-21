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

& $VenvPython -c "import fastapi, httpx" 2>$null
if ($LASTEXITCODE -ne 0) {
    & $VenvPython -m pip install -e "$ProjectDir[api,dev]"
}

$env:PYTHONPATH = Join-Path $ProjectDir "src"
& $VenvPython -m unittest discover -s (Join-Path $ProjectDir "tests") -v

Push-Location $FrontendDir
try {
    & ".\node_modules\.bin\tsc.cmd" --noEmit
    & ".\node_modules\.bin\vinext.cmd" build
    node --test tests/rendered-html.test.mjs
    & ".\node_modules\.bin\eslint.cmd" app lib tests
}
finally {
    Pop-Location
}
