# Builds build\Release\chathistoryplus.dll with CMake and the Ashita SDK at -Sdk. Called by the workflows. The tests are not
# in the release repository (only what runs and builds the plugin is); they run before every deploy instead.
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
} finally { Pop-Location }
