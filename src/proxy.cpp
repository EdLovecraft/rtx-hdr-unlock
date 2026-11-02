// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 EdLovecraft
// Directory-local x64 proxy and InitializeASI plugin. No external process writes.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#define NOMINMAX
#include <windows.h>
#include <ostream>
#include <fstream>
#include <filesystem>
#include <atomic>
#include <mutex>
#include <set>
#include <stdexcept>
#include <winternl.h>

static std::ostream& ProxyTrace();
#define RTXHDR_OUT ProxyTrace()
#define RTXHDR_ERR ProxyTrace()
#include "unlock_core.h"
#include "proxy_exports.h"
#pragma comment(lib, "advapi32.lib")

namespace {
HMODULE gProxyModule = nullptr;
HMODULE gSystemModule = nullptr;
INIT_ONCE gSystemOnce = INIT_ONCE_STATIC_INIT;
INIT_ONCE gPatchOnce = INIT_ONCE_STATIC_INIT;
// 0 waiting, 1 initializing, 2 patched, -1 rejected/failed.
std::atomic<int> gPatchStatus{0};
thread_local bool gInsideInitialization = false;
std::ofstream gTraceFile;
std::ostringstream gSilentTrace;
std::filesystem::path gDirectory;
std::vector<HMODULE> gPinnedDrivers;
bool gLoadTraceCreated = false;

// Only Kernel32 file I/O, fixed-size storage, no waits or initialization of
// graphics/registry/CRT streams. This makes even a load-only ASI diagnosable.
bool ResetLoadTrace(HMODULE module) noexcept {
  const DWORD savedError = GetLastError();
  // Loader callbacks are serialized. Static storage avoids reserving 64 KiB
  // on every thread-attach call if the optimizer inlines this into DllMain;
  // some graphics worker threads have very small stacks.
  static wchar_t path[32768]{};
  const DWORD length = GetModuleFileNameW(module, path, DWORD(std::size(path)));
  bool result = false;
  if (length && length < std::size(path)) {
    DWORD leaf = length;
    while (leaf && path[leaf-1] != L'\\' && path[leaf-1] != L'/') --leaf;
    constexpr wchar_t logLeaf[] = L"RtxHdrUnlock.log";
    if (leaf && leaf + std::size(logLeaf) <= std::size(path)) {
      for (std::size_t i = 0; i < std::size(logLeaf); ++i) path[leaf+i] = logLeaf[i];
      const HANDLE file = CreateFileW(path, GENERIC_WRITE,
          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
          CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
      if (file != INVALID_HANDLE_VALUE) {
        constexpr char message[] =
            "DLL_LOADED: waiting for first proxy call or InitializeASI outside DllMain.\r\n";
        DWORD written = 0;
        result = WriteFile(file, message, sizeof(message)-1, &written, nullptr) &&
                 written == sizeof(message)-1;
        CloseHandle(file);
      }
    }
  }
  SetLastError(savedError);
  return result;
}

std::wstring ModulePath(HMODULE module) {
  std::vector<wchar_t> path(32768);
  const DWORD length = GetModuleFileNameW(module, path.data(), DWORD(path.size()));
  if (!length || length >= path.size()) throw std::runtime_error("GetModuleFileNameW failed");
  return std::wstring(path.data(), length);
}

std::wstring SystemPath(const wchar_t* leaf) {
  wchar_t directory[MAX_PATH]{};
  const UINT length = GetSystemDirectoryW(directory, MAX_PATH);
  if (!length || length >= MAX_PATH) throw std::runtime_error("GetSystemDirectoryW failed");
  return (std::filesystem::path(directory) / leaf).wstring();
}

std::wstring ProxyLibrary() {
  if (!kUniversalProxy) return kProxyLibrary;
  const std::filesystem::path path(ModulePath(gProxyModule));
  const auto leaf = Lower(path.filename().wstring());
  for (const auto* library : kProxyLibraries)
    if (leaf == library) return leaf;
  // The distributed file can also be explicitly initialized as a plugin.
  if (Lower(path.extension().wstring()) == L".asi" || leaf == L"rtxhdrunlock.dll") return L"";
  throw std::runtime_error("Unsupported filename; use dxgi/winmm/version/winhttp/psapi.dll or .asi");
}

// Unlike a notification callback, a proxy export normally executes outside the
// loader lock. Defer expensive initialization if a caller uses it from DllMain.
bool InLoaderCallout() {
  using Query = BOOLEAN(NTAPI*)();
  static const auto query = reinterpret_cast<Query>(GetProcAddress(
      GetModuleHandleW(L"ntdll.dll"), "RtlIsThreadWithinLoaderCallout"));
  return !query || query() != FALSE;
}

std::set<std::filesystem::path> ActiveDriverDirectories() {
  std::set<std::filesystem::path> result;
  // An already loaded module is authoritative; never search stale DriverStore
  // packages for an older version just because its hash is familiar.
  if (HMODULE loaded = GetModuleHandleW(L"nvwgf2umx.dll")) {
    result.insert(std::filesystem::path(ModulePath(loaded)).parent_path());
    return result;
  }
  for (DWORD index = 0;; ++index) {
    DISPLAY_DEVICEW display{};
    display.cb = sizeof(display);
    if (!EnumDisplayDevicesW(nullptr, index, &display, 0)) break;
    if (Lower(display.DeviceID).find(L"ven_10de") == std::wstring::npos) continue;
    std::wstring key(display.DeviceKey);
    constexpr wchar_t prefix[] = L"\\Registry\\Machine\\";
    if (key.compare(0, std::size(prefix)-1, prefix) != 0) continue;
    HKEY registry = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, key.c_str()+std::size(prefix)-1, 0,
                      KEY_QUERY_VALUE, &registry) != ERROR_SUCCESS) continue;
    DWORD type = 0, size = 0;
    LONG status = RegQueryValueExW(registry, L"UserModeDriverName", nullptr, &type, nullptr, &size);
    if (status != ERROR_SUCCESS || (type != REG_MULTI_SZ && type != REG_SZ) ||
        size >= 65536 || size % sizeof(wchar_t)) {
      RegCloseKey(registry);
      continue;
    }
    std::vector<wchar_t> value(size / sizeof(wchar_t) + 2, 0);
    status = RegQueryValueExW(registry, L"UserModeDriverName", nullptr, &type,
                             reinterpret_cast<BYTE*>(value.data()), &size);
    RegCloseKey(registry);
    if (status != ERROR_SUCCESS) continue;
    for (const wchar_t* item = value.data(); *item; item += wcslen(item)+1) {
      const std::filesystem::path path(item);
      const auto leaf = Lower(path.filename().wstring());
      if (path.is_absolute() && (leaf == L"nvwgf2umx.dll" || leaf == L"nvldumdx.dll"))
        result.insert(path.parent_path());
    }
  }
  return result;
}

ModuleInfo LoadedModule(HMODULE handle, const ModuleSpec& spec) {
  ModuleInfo module;
  module.spec = spec;
  module.name = spec.name;
  module.path = ModulePath(handle);
  module.base = reinterpret_cast<std::uintptr_t>(handle);
  IMAGE_DOS_HEADER dos{};
  IMAGE_NT_HEADERS64 nt{};
  if (!ReadRemote(GetCurrentProcess(), module.base, &dos, sizeof(dos)) ||
      dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0 || dos.e_lfanew > 0x100000 ||
      !ReadRemote(GetCurrentProcess(), module.base + dos.e_lfanew, &nt, sizeof(nt)) ||
      nt.Signature != IMAGE_NT_SIGNATURE || nt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
    throw std::runtime_error("Driver PE identity mismatch");
  module.size = nt.OptionalHeader.SizeOfImage;
  return module;
}

bool PatchPreloadedModules(const std::filesystem::path& directory) {
  constexpr int peak = kUnlockCeilingNits;
  std::array<std::wstring, 2> paths;
  // Check BOTH driver files before loading either. Unsupported versions remain
  // completely untouched and the normal system forwarding still works.
  for (std::size_t i = 0; i < kModules.size(); ++i) {
    paths[i] = (directory / kModules[i].name).wstring();
    ModuleInfo file;
    file.spec = kModules[i];
    file.path = paths[i];
    if (!ValidateModuleFile(file)) return false;
  }
  const auto variants = BuildCodeVariants(peak);
  if (!variants) return false;
  std::array<ModuleInfo, 2> modules;
  std::array<CodeVariants, 2> originals;
  for (std::size_t i = 0; i < kModules.size(); ++i) {
    const bool wasLoaded = GetModuleHandleW(kModules[i].name) != nullptr;
    HMODULE handle = LoadLibraryExW(paths[i].c_str(), nullptr,
        LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!handle) throw std::runtime_error("Preload failed: " + LastErrorText());
    // Hold the library until process exit so a reload cannot discard the patch.
    gPinnedDrivers.push_back(handle);
    modules[i] = LoadedModule(handle, kModules[i]);
    ProxyTrace() << "Preloaded " << Narrow(modules[i].path)
                 << "; already_loaded=" << wasLoaded << '\n';
    if (!ValidateModuleFile(modules[i]) || !ValidateSizeField(GetCurrentProcess(), modules[i])) return false;
    for (auto source : kCodeSources) {
      const auto index = std::size_t(source);
      RangeState state;
      int existingPeak = 0;
      if (!QueryRange(GetCurrentProcess(), modules[i], originals[i][index], state, &existingPeak, source) ||
          state == RangeState::kUnknown ||
          (state == RangeState::kPatched && existingPeak != peak)) {
        ProxyTrace() << "Rejected unknown source or different existing peak; no writes.\n";
        return false;
      }
    }
  }
  for (std::size_t i = 0; i < modules.size(); ++i) {
    // These are preloaded, process-local data carriers, before first graphics use.
    // Never invoke the external tool's thread suspension on our own calling thread.
    if (!UpdateModuleSources(GetCurrentProcess(), GetCurrentProcessId(), modules[i],
                             *variants, peak, false, true, true, true)) {
      for (std::size_t earlier = i; earlier-- > 0;) {
        for (auto source : kCodeSources) {
          const auto index = std::size_t(source);
          if (!WriteRemote(GetCurrentProcess(), GetCurrentProcessId(),
                           modules[earlier].base + SourceRva(modules[earlier].spec, source),
                           (*variants)[index], originals[earlier][index], true))
            ProxyTrace() << "ERROR: cross-module rollback could not be confirmed\n";
        }
      }
      return false;
    }
  }
  ProxyTrace() << "PATCH_READY peak=" << peak
               << "; both NVIDIA modules, CUBIN+PTX; requires initialization before first HDR use.\n";
  return true;
}

BOOL CALLBACK InitializePatch(PINIT_ONCE, PVOID, PVOID*) noexcept {
  gPatchStatus.store(1);
  gInsideInitialization = true;
  try {
    gDirectory = std::filesystem::path(ModulePath(gProxyModule)).parent_path();
    const auto log = gDirectory / L"RtxHdrUnlock.log";
    gTraceFile.open(log, std::ios::out | (gLoadTraceCreated ? std::ios::app : std::ios::trunc));
    if (gTraceFile) gTraceFile << std::unitbuf;
    SYSTEMTIME started{};
    GetSystemTime(&started);
    ProxyTrace() << "RTX HDR universal proxy / ASI; pid=" << GetCurrentProcessId()
                 << "; binary=" << Narrow(ModulePath(gProxyModule)) << '\n';
    ProxyTrace() << "Started UTC " << started.wYear << '-' << started.wMonth << '-'
                 << started.wDay << ' ' << started.wHour << ':' << started.wMinute << ':'
                 << started.wSecond << "; log reset at DLL load\n";
    const auto library = ProxyLibrary();
    ProxyTrace() << "Mode=" << (library.empty() ? "ASI/plugin" : Narrow(library)) << '\n';
    ProxyTrace() << "Fixed unlock ceiling=" << kUnlockCeilingNits << " nits\n";
    if (!EnsureCuda89()) {
      gPatchStatus.store(-1);
    } else {
      const auto directories = ActiveDriverDirectories();
      if (directories.size() != 1)
        throw std::runtime_error("Cannot identify one active NVIDIA driver directory; no writes");
      gPatchStatus.store(PatchPreloadedModules(*directories.begin()) ? 2 : -1);
    }
  } catch (const std::exception& error) {
    ProxyTrace() << "REJECTED: " << error.what() << '\n';
    gPatchStatus.store(-1);
  } catch (...) {
    ProxyTrace() << "REJECTED: unexpected initialization error\n";
    gPatchStatus.store(-1);
  }
  gInsideInitialization = false;
  return TRUE;  // Failure is terminal for this process; preserve ordinary forwarding.
}

void EnsurePatch() {
  const int status = gPatchStatus.load(std::memory_order_acquire);
  if (status == 2 || status == -1) return;
  if (gInsideInitialization || InLoaderCallout()) return;
  InitOnceExecuteOnce(&gPatchOnce, InitializePatch, nullptr, nullptr);
}

BOOL CALLBACK InitializeSystem(PINIT_ONCE, PVOID, PVOID*) noexcept {
  try {
    const auto library = ProxyLibrary();
    if (library.empty()) return FALSE;
    const auto path = SystemPath(library.c_str());
    gSystemModule = LoadLibraryExW(path.c_str(), nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (gSystemModule == gProxyModule) gSystemModule = nullptr;
  } catch (...) { gSystemModule = nullptr; }
  return gSystemModule != nullptr;
}
}  // namespace

static std::ostream& ProxyTrace() {
  return gTraceFile.is_open() ? static_cast<std::ostream&>(gTraceFile) : gSilentTrace;
}

extern "C" {
FARPROC ProxyTargets[kProxyExportCount ? kProxyExportCount : 1]{};

FARPROC ProxyResolve(unsigned index) noexcept {
  const DWORD lastError = GetLastError();
  if (index >= kProxyExportCount ||
      !InitOnceExecuteOnce(&gSystemOnce, InitializeSystem, nullptr, nullptr)) {
    RaiseFailFastException(nullptr, nullptr, 0);
    return nullptr;
  }
  EnsurePatch();
  auto* address = reinterpret_cast<void* volatile*>(&ProxyTargets[index]);
  FARPROC target = reinterpret_cast<FARPROC>(InterlockedCompareExchangePointer(address, nullptr, nullptr));
  if (!target) {
    const auto& entry = kProxyExports[index];
    target = GetProcAddress(gSystemModule, entry.name ? entry.name : MAKEINTRESOURCEA(entry.ordinal));
    if (!target) {
      RaiseFailFastException(nullptr, nullptr, 0);
      return nullptr;
    }
    InterlockedCompareExchangePointer(address, reinterpret_cast<void*>(target), nullptr);
  }
  SetLastError(lastError);
  return target;
}

__declspec(dllexport) void InitializeASI() { EnsurePatch(); }
__declspec(dllexport) int RtxHdrUnlockInitialize() { EnsurePatch(); return gPatchStatus.load(); }
__declspec(dllexport) int RtxHdrUnlockGetStatus() { return gPatchStatus.load(); }
}

BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID) {
  if (reason == DLL_PROCESS_ATTACH) {
    gProxyModule = module;
    gLoadTraceCreated = ResetLoadTrace(module);
  }
  return TRUE;
}
