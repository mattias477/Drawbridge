[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',
    [switch]$SkipInstaller
)

$ErrorActionPreference = 'Stop'
$repoRoot = $PSScriptRoot
$artifactsRoot = Join-Path $repoRoot 'artifacts'
$publishRoot = Join-Path $artifactsRoot 'publish'
$serviceOutput = Join-Path $publishRoot 'service'
$appOutput = Join-Path $publishRoot 'app'

function Invoke-CheckedProcess {
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,

        [Parameter(Mandatory)]
        [string[]]$ArgumentList
    )

    & $FilePath @ArgumentList
    if ($LASTEXITCODE -ne 0) {
        throw "'$FilePath' failed with exit code $LASTEXITCODE."
    }
}

foreach ($publishOutput in @($serviceOutput, $appOutput)) {
    if (Test-Path -LiteralPath $publishOutput) {
        Remove-Item -LiteralPath $publishOutput -Recurse -Force
    }
}

$solution = Join-Path $repoRoot 'Drawbridge.sln'
$testsAssembly = Join-Path $repoRoot "Drawbridge.Core.Tests\bin\$Configuration\net8.0\Drawbridge.Core.Tests.dll"

Invoke-CheckedProcess 'dotnet' @('restore', $solution)
Invoke-CheckedProcess 'dotnet' @('build', $solution, '-c', $Configuration, '--no-restore', '-p:TreatWarningsAsErrors=true')
Invoke-CheckedProcess 'dotnet' @('exec', '--roll-forward', 'Major', $testsAssembly)
Invoke-CheckedProcess 'dotnet' @('publish', (Join-Path $repoRoot 'Drawbridge.Service'), '-c', $Configuration, '-r', 'win-x64', '--self-contained', 'true', '-o', $serviceOutput)
Invoke-CheckedProcess 'dotnet' @('publish', (Join-Path $repoRoot 'Drawbridge.App'), '-c', $Configuration, '-r', 'win-x64', '--self-contained', 'true', '-o', $appOutput)

if ($SkipInstaller) {
    return
}

$isccCandidates = @(@(
    (Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe'),
    (Join-Path $env:ProgramFiles 'Inno Setup 6\ISCC.exe'),
    (Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 6\ISCC.exe'),
    (Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 7\ISCC.exe'),
    (Join-Path $env:ProgramFiles 'Inno Setup 7\ISCC.exe'),
    (Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 7\ISCC.exe')
) | Where-Object { $_ -and (Test-Path -LiteralPath $_) })

if ($isccCandidates.Count -eq 0) {
    throw 'Inno Setup 6.4 or newer was not found. Install it or run with -SkipInstaller.'
}

Invoke-CheckedProcess $isccCandidates[0] @('/Qp', (Join-Path $repoRoot 'drawbridge.iss'))
