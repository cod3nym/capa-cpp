<#
.SYNOPSIS
    Builds ida-capa, the capa plugin for IDA Pro.

.DESCRIPTION
    Produces build\<Configuration>\ida-capa.dll.

.PARAMETER Configuration
    Release (default) or Debug. Note that Debug still links the *release* CRT --
    see the comment in ida-capa.vcxproj for why.

.PARAMETER Install
    Also copy the DLL into the IDA user plugins directory.
#>
[CmdletBinding()]
param(
    [ValidateSet('Release', 'Debug')]
    [string]$Configuration = 'Release',
    [switch]$Install
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$outDir = Join-Path $root "build\$Configuration"

function Find-Tool {
    param([string]$Name, [string[]]$Candidates)
    foreach ($c in $Candidates) {
        if (Test-Path $c) { return $c }
    }
    $onPath = Get-Command $Name -ErrorAction SilentlyContinue
    if ($null -ne $onPath) { return $onPath.Source }
    throw "cannot find $Name; looked in: $($Candidates -join ', ')"
}

$msbuild = Find-Tool 'MSBuild.exe' @(
    'C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe',
    'C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe'
)

Write-Host "==> building ida-capa" -ForegroundColor Cyan
# /m:1 is deliberate: parallel cl.exe instances race on the shared PDB and fail
# with C1041.
& $msbuild (Join-Path $PSScriptRoot 'ida-capa.vcxproj') `
    /p:Configuration=$Configuration /p:Platform=x64 /m:1 /v:minimal /nologo
if ($LASTEXITCODE -ne 0) { throw "plugin build failed" }

Write-Host "`n==> output in $outDir" -ForegroundColor Green
Get-ChildItem $outDir -Filter ida-capa.dll | ForEach-Object {
    "{0,-20} {1,10:N0} bytes" -f $_.Name, $_.Length
}

if ($Install) {
    # IDA keeps the plugin DLL open for as long as it runs, so installing over a live
    # IDA either fails outright or -- worse -- appears to work while the old binary
    # stays loaded. Every symptom then looks like a bug that was already fixed, which
    # is a genuinely expensive way to lose an afternoon.
    $ida = Get-Process -Name ida, ida64, idat, idat64 -ErrorAction SilentlyContinue
    if ($null -ne $ida) {
        throw ("IDA is running (PID $($ida.Id -join ', ')). Close it before installing, " +
               "or the DLL cannot be replaced and IDA will keep running the old build.")
    }

    $pluginDir = Join-Path $env:APPDATA 'Hex-Rays\IDA Pro\plugins'
    if (-not (Test-Path $pluginDir)) {
        New-Item -ItemType Directory -Path $pluginDir -Force | Out-Null
    }
    $src = Join-Path $outDir 'ida-capa.dll'
    $dst = Join-Path $pluginDir 'ida-capa.dll'
    Copy-Item $src -Destination $dst -Force

    # Verify rather than assume: confirm the bytes actually landed.
    $srcHash = (Get-FileHash $src -Algorithm SHA256).Hash
    $dstHash = (Get-FileHash $dst -Algorithm SHA256).Hash
    if ($srcHash -ne $dstHash) {
        throw "installed copy at $dst does not match the build output -- it was not replaced"
    }
    Write-Host "==> installed to $pluginDir" -ForegroundColor Green
    Write-Host ("    {0}  sha256 {1}" -f (Get-Item $dst).LastWriteTime, $dstHash.Substring(0, 16))
    Write-Host "    IDA prints its build stamp on load: 'capa: ida-capa loaded (build ...)'"
}
