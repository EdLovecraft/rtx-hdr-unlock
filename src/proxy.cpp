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

ModuleInfo LoadedModule(HMODULE handle, const wchar_t* name) {
  ModuleInfo module;
  module.name = name;
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

struct PlannedCarrier {
  Carrier carrier;
  std::vector<std::uint8_t> original;
  std::vector<std::uint8_t> patched;
};

struct ModulePlan {
  const wchar_t* name = nullptr;
  std::wstring path;
  std::vector<PlannedCarrier> carriers;
};

// Driver-version independent. Every truehdr_drtm carrier in BOTH driver files is
// located and classified before either module is loaded; a rejection loads
// nothing and leaves normal forwarding intact. A module is loaded only when it
// holds a carrier this GPU can execute, and the loaded bytes must equal the
// classified file bytes (or the exact target patch) before anything is written.
bool PatchPreloadedModules(const std::filesystem::path& directory) {
  constexpr int peak = kUnlockCeilingNits;
  std::array<ModulePlan, kDriverModules.size()> plans;
  std::size_t usable = 0;
  std::size_t structural = 0;
  for (std::size_t i = 0; i < plans.size(); ++i) {
    ModulePlan& plan = plans[i];
    plan.name = kDriverModules[i];
    plan.path = (directory / plan.name).wstring();
    MappedFile file;
    if (!MapReadOnly(plan.path, file)) {
      ProxyTrace() << "WARNING: cannot map " << Narrow(plan.path) << " (" << LastErrorText()
                   << "); this module is skipped\n";
      continue;
    }
    std::vector<Carrier> carriers;
    std::string error;
    if (!ScanImage(file.view, file.size, true, carriers, error)) {
      ProxyTrace() << "REJECTED: " << Narrow(plan.path) << ": " << error << "; nothing was loaded\n";
      return false;
    }
    ProxyTrace() << Narrow(plan.path) << ": " << carriers.size() << " truehdr_drtm carrier(s)\n";
    for (auto& carrier : carriers) {
      carrier.usable = UsableOn(carrier, kSupportedSm);
      ClassifyCarrier(carrier, peak);
      ProxyTrace() << "  " << DescribeCarrier(carrier) << '\n';
    }
    for (auto& carrier : carriers) {
      if (!carrier.usable) continue;
      if (carrier.state != CarrierState::kOriginal) {
        ProxyTrace() << "REJECTED: a carrier this GPU can execute is "
                     << (carrier.state == CarrierState::kPatched ? "already modified in the driver file"
                                                                 : "not structurally recognized")
                     << "; nothing was loaded\n";
        return false;
      }
      PlannedCarrier planned{carrier, {carrier.view, carrier.view + carrier.size}, {}};
      auto patched = BuildPatchedCarrier(carrier, planned.original.data(), peak);
      if (!patched) {
        ProxyTrace() << "REJECTED: could not build the patched carrier; nothing was loaded\n";
        return false;
      }
      if (carrier.known && Sha256Hex(patched->data(), patched->size()) != carrier.known->patched) {
        ProxyTrace() << "REJECTED: the patch of a validated carrier does not reproduce the validated "
                        "result; nothing was loaded\n";
        return false;
      }
      structural += carrier.known ? 0 : 1;
      planned.patched = std::move(*patched);
      planned.carrier.view = nullptr;  // the file view is unmapped when this scope ends
      plan.carriers.push_back(std::move(planned));
    }
    usable += plan.carriers.size();
    if (plan.carriers.empty())
      ProxyTrace() << "WARNING: " << Narrow(plan.name)
                   << " has no carrier executable on SM 8.9; it is not loaded or patched\n";
  }
  if (!usable) {
    ProxyTrace() << "REJECTED: no truehdr_drtm carrier executable on SM 8.9 was found; "
                    "nothing was loaded\n";
    return false;
  }

  std::vector<CarrierWrite> writes;
  std::size_t already = 0;
  for (const auto& plan : plans) {
    if (plan.carriers.empty()) continue;
    const bool wasLoaded = GetModuleHandleW(plan.name) != nullptr;
    HMODULE handle = LoadLibraryExW(plan.path.c_str(), nullptr,
        LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!handle) throw std::runtime_error("Preload failed: " + LastErrorText());
    // Hold the library until process exit so a reload cannot discard the patch.
    gPinnedDrivers.push_back(handle);
    const ModuleInfo module = LoadedModule(handle, plan.name);
    ProxyTrace() << "Preloaded " << Narrow(module.path) << "; already_loaded=" << wasLoaded << '\n';
    for (const auto& planned : plan.carriers) {
      const Carrier& carrier = planned.carrier;
      const std::string label = Narrow(plan.name) + (carrier.kind == CarrierKind::kCubin ? " CUBIN" : " PTX");
      std::vector<std::uint8_t> current(carrier.size);
      const std::uintptr_t address = module.base + carrier.rva;
      if (carrier.rva > module.size || carrier.size > module.size - carrier.rva ||
          !IsRangeReadable(GetCurrentProcess(), address, current.size()) ||
          !ReadRemote(GetCurrentProcess(), address, current.data(), current.size())) {
        ProxyTrace() << "REJECTED: " << label << " is not readable in the loaded image; no writes\n";
        return false;
      }
      if (current == planned.original) {
        writes.push_back({label, address, planned.original, planned.patched});
      } else if (current == planned.patched) {
        ++already;
      } else {
        ProxyTrace() << "REJECTED: loaded " << label
                     << " differs from the driver file and from the target patch; no writes\n";
        return false;
      }
    }
  }
  // These are preloaded, process-local data carriers, before first graphics use.
  // Never invoke the external tool's thread suspension on our own calling thread.
  if (!writes.empty() &&
      !ApplyCarrierWrites(GetCurrentProcess(), GetCurrentProcessId(), writes, true)) {
    ProxyTrace() << "REJECTED: the write transaction failed and was rolled back\n";
    return false;
  }
  ProxyTrace() << "PATCH_READY peak=" << peak << "; tier="
               << (structural ? "structural (" + std::to_string(structural) +
                                    " carrier(s) not byte-identical to a validated release)"
                              : std::string("known"))
               << "; carriers=" << usable << " (" << writes.size() << " written, " << already
               << " already patched); requires initialization before first HDR use.\n";
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
    ProxyTrace() << "Carrier discovery: content scan of the active driver files; "
                    "no driver version, file hash or RVA pin\n";
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
