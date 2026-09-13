<#
.SYNOPSIS
    Run every pre-release check, including the ones too slow for a git hook.

.DESCRIPTION
    The pre-push hook covers what must never reach the public remote. This
    covers what should be true before tagging a release, and adds the two checks
    a hook cannot afford: the production frontend build and a full container
    build with a demo-mode probe.

    The container check is the one that matters most and is easiest to skip. It
    is the only thing that exercises the built dashboard the way a user actually
    receives it -- served as static assets by the backend, rather than by the
    Vite dev server. A frontend that builds but does not serve looks identical
    to a healthy one until someone opens it.

    Nothing here is new logic; it is the sequence that was verified by hand
    during the migration, written down so it is repeatable.

.PARAMETER SkipContainer
    Skip the Docker build and probe. Use when Docker Desktop is not running and
    you only want the fast checks.

.EXAMPLE
    .\scripts\Verify-Release.ps1
#>
[CmdletBinding()]
param(
    [switch] $SkipContainer
)

# Continue, not Stop. Every check here is judged by its exit code, and under
# Windows PowerShell 5.1 a native command's redirected stderr becomes an
# ErrorRecord that 'Stop' turns into a terminating error -- so npm printing a
# warning, or docker printing build progress, would abort the whole run.
$ErrorActionPreference = 'Continue'
$RepoRoot = Split-Path -Parent $PSScriptRoot
$script:Failures = @()

function Write-Head {
    param([string] $Text)
    Write-Host ''
    Write-Host "== $Text" -ForegroundColor Cyan
}

function Record {
    param([string] $Name, [bool] $Ok, [string] $Detail = '')
    if ($Ok) {
        Write-Host '  PASS  ' -ForegroundColor Green -NoNewline
        Write-Host $Name
    }
    else {
        Write-Host '  FAIL  ' -ForegroundColor Red -NoNewline
        Write-Host $Name
        if ($Detail) { Write-Host "        $Detail" -ForegroundColor DarkGray }
        $script:Failures += $Name
    }
}

# Prefer the project venv; fall back to whatever python is on PATH.
$Python = 'python'
$venvPy = Join-Path $RepoRoot 'backend\.venv\Scripts\python.exe'
if (Test-Path -LiteralPath $venvPy) { $Python = $venvPy }

# ------------------------------------------------------------------ versions --

Write-Head 'Versions'

$pyVersion = (Select-String -LiteralPath (Join-Path $RepoRoot 'backend\pyproject.toml') `
    -Pattern '^version\s*=\s*"([^"]+)"' | Select-Object -First 1).Matches[0].Groups[1].Value
$jsVersion = (Select-String -LiteralPath (Join-Path $RepoRoot 'frontend\package.json') `
    -Pattern '"version"\s*:\s*"([^"]+)"' | Select-Object -First 1).Matches[0].Groups[1].Value

# backend/app/api/app.py is what /api/health reports, so it is the version a bug
# report quotes. release.yml checks it alongside the other two; this check left
# it out at first, which meant a local "all clear" could still fail in CI.
$appVersion = (Select-String -LiteralPath (Join-Path $RepoRoot 'backend\app\api\app.py') `
    -Pattern '^_VERSION = "([^"]+)"$' | Select-Object -First 1).Matches[0].Groups[1].Value

$versionsAgree = ($appVersion -eq $pyVersion) -and ($pyVersion -eq $jsVersion)
Record "version strings agree ($pyVersion)" $versionsAgree `
    "app.py=$appVersion pyproject=$pyVersion package.json=$jsVersion -- the release workflow gates on all three and the tag"

# ---------------------------------------------------------------------- spec --

Write-Head 'Specification'

$specOut = & $Python (Join-Path $RepoRoot 'scripts\check_spec_citations.py') 2>&1
Record 'every citation resolves, every criterion cited' ($LASTEXITCODE -eq 0) ($specOut -join ' ')

# ------------------------------------------------------------------- backend --

Write-Head 'Backend'

Push-Location (Join-Path $RepoRoot 'backend')
try {
    $pytest = & $Python -m pytest -q 2>&1
    $summary = ($pytest | Select-String -Pattern '\d+ passed' | Select-Object -Last 1)
    Record "test suite$(if ($summary) { ' -- ' + $summary.Line.Trim() })" ($LASTEXITCODE -eq 0) `
        (($pytest | Select-Object -Last 5) -join "`n        ")

    $heads = & $Python -m alembic heads 2>&1
    $headCount = @($heads | Select-String -Pattern '\(head\)').Count
    Record "exactly one Alembic head" ($headCount -eq 1) `
        "found $headCount -- CI gates on this, and two heads means a migration branch"
}
finally { Pop-Location }

# ------------------------------------------------------------------ frontend --

Write-Head 'Frontend'

Push-Location (Join-Path $RepoRoot 'frontend')
try {
    $null = & npx tsc --noEmit 2>&1
    Record 'typecheck' ($LASTEXITCODE -eq 0)

    $vitest = & npm test --silent 2>&1
    $summary = ($vitest | Select-String -Pattern 'Tests\s+\d+ passed' | Select-Object -Last 1)
    Record "test suite$(if ($summary) { ' -- ' + $summary.Line.Trim() })" ($LASTEXITCODE -eq 0) `
        (($vitest | Select-Object -Last 5) -join "`n        ")

    $build = & npm run build 2>&1
    $buildOk = ($LASTEXITCODE -eq 0)
    Record 'production build' $buildOk (($build | Select-Object -Last 5) -join "`n        ")

    if ($buildOk) {
        # The fonts are vendored precisely so the dashboard fetches nothing from
        # a CDN -- this scanner runs on isolated networks where a CDN request
        # never resolves. A build that silently drops them is a regression.
        $fonts = @(Get-ChildItem -LiteralPath 'dist\assets' -Filter '*.woff2' -ErrorAction SilentlyContinue)
        Record "all four vendored fonts emitted (found $($fonts.Count))" ($fonts.Count -eq 4)
    }

    $audit = & npm audit --audit-level=low 2>&1
    Record 'npm audit clean' ($LASTEXITCODE -eq 0) `
        (($audit | Select-String -Pattern 'vulnerabilit' | Select-Object -Last 1) -join '')
}
finally { Pop-Location }

# ----------------------------------------------------------------- container --

if ($SkipContainer) {
    Write-Head 'Container'
    Write-Host '  SKIP  -SkipContainer was given' -ForegroundColor Yellow
}
else {
    Write-Head 'Container'

    $dockerUp = $false
    try {
        $null = & docker info --format '{{.ServerVersion}}' 2>&1
        $dockerUp = ($LASTEXITCODE -eq 0)
    }
    catch { $dockerUp = $false }

    if (-not $dockerUp) {
        Record 'Docker daemon reachable' $false 'start Docker Desktop, or pass -SkipContainer'
    }
    else {
        $build = & docker build -t cvedeck:verify $RepoRoot 2>&1
        $imageOk = ($LASTEXITCODE -eq 0)
        Record 'image builds' $imageOk (($build | Select-Object -Last 8) -join "`n        ")

        if ($imageOk) {
            $null = & docker rm -f cvedeck-verify 2>&1
            $null = & docker run -d --name cvedeck-verify -p 8099:8000 `
                -e CVEDECK_DEMO_MODE=1 cvedeck:verify 2>&1
            try {
                $health = $null
                foreach ($attempt in 1..15) {
                    Start-Sleep -Seconds 2
                    try {
                        $health = Invoke-RestMethod -Uri 'http://localhost:8099/api/health' -TimeoutSec 3
                        break
                    }
                    catch { $health = $null }
                }

                Record 'container reports healthy' ($null -ne $health)

                if ($null -ne $health) {
                    Record 'demo mode reported at /api/health' ($health.capabilities.demo_mode -eq $true)

                    # The refusal is the point of demo mode: each of these takes
                    # a user-supplied address and connects to it, so a public
                    # instance with them enabled is an open scanner.
                    foreach ($route in @('/api/scans', '/api/discovery/sweep', '/api/scans/test-connection')) {
                        $code = 0
                        try {
                            $resp = Invoke-WebRequest -Uri "http://localhost:8099$route" -Method POST `
                                -Body '{}' -ContentType 'application/json' -TimeoutSec 5 `
                                -UseBasicParsing -ErrorAction Stop
                            $code = $resp.StatusCode
                        }
                        catch {
                            if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
                        }
                        Record "POST $route refused with 403 (got $code)" ($code -eq 403)
                    }

                    $index = Invoke-WebRequest -Uri 'http://localhost:8099/' -TimeoutSec 5 -UseBasicParsing
                    $assets = [regex]::Matches($index.Content, '/assets/[A-Za-z0-9._-]+') |
                        ForEach-Object { $_.Value } | Select-Object -Unique
                    $servedOk = $assets.Count -gt 0
                    foreach ($asset in $assets) {
                        try {
                            $a = Invoke-WebRequest -Uri "http://localhost:8099$asset" -TimeoutSec 5 -UseBasicParsing
                            if ($a.StatusCode -ne 200) { $servedOk = $false }
                        }
                        catch { $servedOk = $false }
                    }
                    Record "dashboard and its $($assets.Count) hashed asset(s) served" $servedOk
                }
            }
            finally {
                $null = & docker rm -f cvedeck-verify 2>&1
                $null = & docker rmi cvedeck:verify 2>&1
            }
        }
    }
}

# ------------------------------------------------------------------- summary --

Write-Host ''
if ($script:Failures.Count -gt 0) {
    Write-Host ("  $($script:Failures.Count) check(s) failed:") -ForegroundColor Red
    foreach ($f in $script:Failures) { Write-Host "    - $f" }
    Write-Host ''
    exit 1
}

Write-Host "  Release checks passed for version $pyVersion." -ForegroundColor Green
Write-Host ''
Write-Host '  To release:' -ForegroundColor DarkGray
Write-Host "      git tag v$pyVersion" -ForegroundColor DarkGray
Write-Host "      git push origin v$pyVersion" -ForegroundColor DarkGray
Write-Host ''
exit 0
