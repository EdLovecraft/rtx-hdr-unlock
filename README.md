# RTX HDR Unlock

**English** | **[简体中文](README.zh-CN.md)**

RTX HDR Unlock fixes a long-standing issue that has affected NVIDIA RTX HDR since release: even when the slider allows up to **2000 nits**, the internal tone-mapping kernel clips highlights around **1000 nits**.

This project raises the internal highlight ceiling in memory to a true **2000 nits**, while keeping NVIDIA's original Oklab gamut-mapping path and normal brightness control intact.

## What Problem This Fixes

In standard RTX HDR, setting peak brightness above 1000 nits (for example **2000 nits**) still hits an internal 1.0 normalized ceiling (`1.0 = 1000 nits`). Bright highlights flatten around **1000 nits**, and bright steps near white merge into the same value.

With this DLL loaded:

- The internal clipping ceiling becomes **2000 nits**.
- Your actual target peak still comes from your **NVIDIA App / RTX HDR Peak Brightness** setting.
- If your display is **2000 nits**, keep NVIDIA set to **2000**; it does **not** force every scene to 2000 nits.
- System driver files on disk are never modified.

## How to Use

### 1. Build or obtain `RtxHdrUnlock.dll`

One compiled binary works as a proxy DLL or as an `.asi` plugin.

### 2. Place it next to the game's main `.exe`

Copy `RtxHdrUnlock.dll` into the same folder as the target executable, then rename it to **one** DLL name that the game actually loads:

- `dxgi.dll` (good default for most DirectX 11 / 12 games)
- `winmm.dll`
- `version.dll`
- `winhttp.dll`
- `psapi.dll`

Or, if the game already uses an ASI Loader, rename it to any `.asi` name such as:

- `RtxHdrUnlock.asi`

### 3. Launch the game

When the file loads, it creates `RtxHdrUnlock.log` in the same folder and clears previous log contents on every new load:

- `DLL_LOADED`: the file was loaded into the process.
- `PATCH_READY`: every RTX HDR kernel copy (`CUBIN` and `PTX`) that this GPU can run was found in the NVIDIA driver modules, verified, and patched in memory. `tier=known` means the kernel is byte-identical to one validated for this release; `tier=structural` means a newer driver build whose kernel still has exactly the expected structure.
- `REJECTED`: the GPU architecture or a kernel did not match the expected structure, so nothing was changed.

### Important Notes

- Do **not** overwrite a file that the game itself already ships in that folder, and do not overwrite an existing ReShade / Special K proxy. Pick another supported filename instead.
- `psapi.dll` is listed in Windows `KnownDLLs`. Normal name-based imports load Windows' system copy first, so `psapi.dll` only works when a host or loader explicitly loads the local file by full path. For ordinary game folder placement, prefer `dxgi.dll`, `winmm.dll`, `version.dll`, or `winhttp.dll`.
- `.asi` mode requires an ASI Loader that calls `InitializeASI` outside `DllMain` before RTX HDR initializes.
- To uninstall, close the game and delete the DLL / ASI file (and `RtxHdrUnlock.log` if present).

## How It Works

NVIDIA's `truehdr_drtm` CUDA kernel receives the user's configured peak brightness, divides it by `1000.0`, and uses that normalized value during tone mapping. However, the Oklab gamut-mapping stage still contains hard-coded upper bounds for a `1000`-nit ceiling:

1. An upper domain tolerance check at `1.001` (`(1000 + 1) / 1000`).
2. Final channel clamp instructions capped at `1.0` (`1000 / 1000`).

Because of those constants, values above `1.0` are pulled back to roughly 1000 nits even when the kernel parameter requests 2000 nits.

`RtxHdrUnlock.dll` fixes this in process memory before RTX HDR runs:

1. In `DllMain`, it only records the module handle and writes the initial `DLL_LOADED` line to `RtxHdrUnlock.log`. It avoids heavy work inside the Windows loader lock.
2. On the first forwarded export call (or `InitializeASI`), it locates the active NVIDIA driver folder and, **before loading anything**, scans `nvAIHDRx.dll` and `nvwgf2umx.dll` on disk for every embedded `truehdr_drtm` kernel: native **CUBIN** images (CUDA ELF, both the current and the CUDA 13 format) and **PTX** text. Nothing is tied to a driver version, file hash, or memory address.
3. For each kernel copy this GPU can run (an SM 8.x CUBIN or the PTX), it derives the patch locations from the code itself: the 18 Oklab in-gamut tests against `1.001` (each paired with its `-0.001` test) and, on the same candidate channels, the final `min(c, 1.0)` clamps, whether compiled as compare-and-select or as a single minimum instruction. Any deviation from that structure rejects the whole patch.
4. It preloads only the modules that hold such a kernel, confirms the loaded bytes equal the file, and changes only those upper-bound constants (tolerance to `2.001`, clamp to `2.0`): **36** per kernel in current drivers. Blob lengths, register counts, and the surrounding algorithm stay unchanged.
5. Every write is verified by readback. If any step fails, all modified bytes and memory protections in both modules are rolled back automatically.

```mermaid
flowchart LR
  A[Game loads renamed DLL or ASI] --> B[First API call / InitializeASI]
  B --> C[Scan nvAIHDRx.dll and nvwgf2umx.dll on disk for truehdr_drtm CUBIN/PTX]
  C --> D[Locate the Oklab tolerance tests and ceiling clamps; reject any mismatch]
  D --> E[Preload modules and patch the located constants to 2000 nits]
  E --> F[Readback check and flush instruction cache]
  F --> G[Forward calls to real System32 DLL]
```

## How to Build

### Prerequisites

- Windows 10 / 11 x64
- Python 3 with `pefile` (`pip install pefile`)
- LLVM `clang-cl.exe` (`C:/Program Files/LLVM/bin/clang-cl.exe`)
- Visual Studio 2022 `ml64.exe` (or LLVM `llvm-ml64.exe`) and Windows SDK libraries

If your `clang-cl.exe` or `ml64.exe` is installed in a different path, update the two path variables at the top of `tools/build_proxy.ps1`.

### Build Command

Run from the repository root in PowerShell:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\build_proxy.ps1
```

The build script:

1. Runs `tools/generate_proxy_exports.py` against your local `System32` DLLs (`dxgi`, `winmm`, `version`, `winhttp`, `psapi`) to generate x64 assembly forwarding thunks (`analysis/proxy_build/universal/`).
2. Assembles the thunks, preserving integer registers (`RCX`, `RDX`, `R8`, `R9`), `XMM0–XMM3`, and caller stack arguments.
3. Compiles `src/proxy.cpp` into `dist/RtxHdrUnlock.dll`.

## Compatibility & Safety

- Not tied to a driver version. The same binary was verified with NVIDIA **616.92, 617.42, 621.01, and 621.14** x64. Every kernel copy those drivers contain is byte-identical across them (616.92 and 617.42 have no PTX copy yet); only the locations changed.
- A future driver that recompiles the kernel is still patched when the code keeps the same structure (reported as `tier=structural`). If the structure differs, the DLL refuses to patch and still forwards normal system DLL calls cleanly.
- Requires an **Ada (`SM 8.9`)** GPU, as before.
- After a driver update, `python tools/carrier_locator.py` shows what the DLL will do with the installed driver, and `python tools/carrier_locator.py --cuda-ab` (requires `numpy`) repeats the highlight check in a separate CUDA process.
