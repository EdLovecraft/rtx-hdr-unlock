param([string[]]$Kinds = @('universal'))
$ErrorActionPreference = 'Stop'
$workspace = Split-Path -Parent $PSScriptRoot
$buildRoot = Join-Path $workspace 'analysis/proxy_build'
$distRoot = Join-Path $workspace 'dist/proxy'
$clang = 'C:/Program Files/LLVM/bin/clang-cl.exe'
$assembler = 'D:/Microsoft Visual Studio/2022/Community/VC/Tools/MSVC/14.44.35207/bin/Hostx64/x64/ml64.exe'
if (-not (Test-Path -LiteralPath $assembler)) { $assembler = 'C:/Program Files/LLVM/bin/llvm-ml64.exe' }
foreach ($kind in $Kinds) {
    if ($kind -notin @('dxgi', 'winmm', 'version', 'winhttp', 'psapi', 'asi', 'universal')) { throw "Unknown proxy kind: $kind" }
    $build = Join-Path $buildRoot $kind
    $output = if ($kind -eq 'universal') { Join-Path $workspace 'dist' } else { Join-Path $distRoot $kind }
    New-Item -ItemType Directory -Path $build, $output -Force | Out-Null
    & python (Join-Path $PSScriptRoot 'generate_proxy_exports.py') $kind $build
    if ($LASTEXITCODE -ne 0) { throw 'Export generation failed' }
    $linkObjects = @()
    if ($kind -ne 'asi') {
        & $assembler /nologo /c "/Fo$build/proxy_thunks.obj" (Join-Path $build 'proxy.asm')
        if ($LASTEXITCODE -ne 0) { throw 'Thunk assembly failed' }
        $linkObjects += (Join-Path $build 'proxy_thunks.obj')
    }
    $filename = if ($kind -eq 'universal') { 'RtxHdrUnlock.dll' } elseif ($kind -eq 'asi') { 'RtxHdrUnlock.asi' } else { "$kind.dll" }
    & $clang /nologo /utf-8 /std:c++17 /O2 /EHsc /MT /LD /W3 -Wno-unused-function /DUNICODE /D_UNICODE `
        /I (Join-Path $workspace 'src') /I $build (Join-Path $workspace 'src/proxy.cpp') `
        "/Fo$build/proxy.obj" "/Fe$output/$filename" /link @linkObjects `
        "/DEF:$build/proxy.def" "/IMPLIB:$build/proxy.lib" /MACHINE:X64 /INCREMENTAL:NO /OPT:REF /OPT:ICF
    if ($LASTEXITCODE -ne 0) { throw "Proxy build failed: $kind" }
    Get-FileHash -LiteralPath (Join-Path $output $filename) -Algorithm SHA256
}
