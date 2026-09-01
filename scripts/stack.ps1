param(
    [ValidateSet("up", "down", "reset", "status", "logs")]
    [string]$Action = "up"
)

$ErrorActionPreference = "Stop"
$repository = Split-Path -Parent $PSScriptRoot
Push-Location $repository
try {
    $compose = Get-Command docker-compose -ErrorAction SilentlyContinue
    if ($compose) {
        $standalone = $compose.Source
    }
    elseif ((docker compose version 2>$null)) {
        $standalone = $null
    }
    else {
        throw "Docker Compose is not installed or available on PATH."
    }

    function Invoke-StackCompose([string[]]$Arguments) {
        if ($standalone) { & $standalone @Arguments }
        else { & docker compose @Arguments }
        if ($LASTEXITCODE -ne 0) { throw "Docker Compose exited with $LASTEXITCODE." }
    }

    switch ($Action) {
        "up" { Invoke-StackCompose @("up", "--build", "-d", "--wait") }
        "down" { Invoke-StackCompose @("down") }
        "reset" { Invoke-StackCompose @("down", "--volumes", "--remove-orphans") }
        "status" { Invoke-StackCompose @("ps") }
        "logs" { Invoke-StackCompose @("logs", "--follow", "--tail", "200") }
    }
}
finally {
    Pop-Location
}
