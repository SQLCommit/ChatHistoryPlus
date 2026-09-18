# Builds build\Release\chathistoryplus.dll with CMake and the Ashita SDK at -Sdk, then runs the tests if this source has them (no game needed). Called by the workflows.
param([Parameter(Mandatory = $true)][string]$Sdk)
$ErrorActionPreference = 'Stop'
Push-Location (Join-Path $PSScriptRoot '../..')
try {
    $env:ASHITA4_SDK_PATH = $Sdk
    # FindAshitaSDK.cmake applies its release compiler and linker options only when CMAKE_BUILD_TYPE is Release.
    cmake -S . -B build -G 'Visual Studio 17 2022' -A Win32 -DCMAKE_BUILD_TYPE=Release | Out-Host
    if ($LASTEXITCODE) { throw "CMake could not configure the build (exit $LASTEXITCODE)." }
    cmake --build build --config Release | Out-Host
    if ($LASTEXITCODE) { throw "The build failed (exit $LASTEXITCODE)." }
    if (Test-Path tests\run.cmd) {   # an older release's source may not carry the tests
        cmd /c tests\run.cmd | Out-Host
        if ($LASTEXITCODE) { throw "The tests failed (exit $LASTEXITCODE)." }
    } else {
        Write-Host '::warning::This source has no tests\run.cmd; only the build was checked.'
    }
} finally { Pop-Location }
