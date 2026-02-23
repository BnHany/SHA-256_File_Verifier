param(
    [ValidateSet("Debug", "Release", "RelWithDebInfo", "MinSizeRel")]
    [string]$Config = "Release",
    [switch]$Clean,
    [string]$Generator = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

$buildDir = Join-Path $scriptDir "build"

if ($Clean -and (Test-Path -LiteralPath $buildDir)) {
    Write-Host "Cleaning build directory: $buildDir"
    cmd /c rmdir /s /q "$buildDir"
    if (Test-Path -LiteralPath $buildDir) {
        throw "Failed to remove build directory."
    }
}

$configureArgs = @("-S", $scriptDir, "-B", $buildDir)
if ($Generator -ne "") {
    $configureArgs += @("-G", $Generator)
}

Write-Host "Configuring project with CMake..."
& cmake @configureArgs
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

Write-Host "Building target (Config=$Config)..."
& cmake --build $buildDir --config $Config
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

$possibleOutputs = @(
    (Join-Path $buildDir "hash_verifier_gui.exe"),
    (Join-Path (Join-Path $buildDir $Config) "hash_verifier_gui.exe")
)

foreach ($output in $possibleOutputs) {
    if (Test-Path -LiteralPath $output) {
        Write-Host "Build output: $output"
        break
    }
}

Write-Host "Build completed successfully."
