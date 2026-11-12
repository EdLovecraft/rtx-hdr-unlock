// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 EdLovecraft
#pragma once
// Shared, driver-version-independent kernel discovery, validation and patch
// transaction. Nothing is pinned to RVAs, file offsets or driver file hashes:
// every truehdr_drtm CUBIN/PTX carrier is located by content, and its patch
// sites are derived from the code itself. Any deviation from the expected
// structure rejects the whole patch.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <tlhelp32.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#pragma comment(lib, "user32.lib")

#ifndef RTXHDR_OUT
#define RTXHDR_OUT std::cout
#endif
#ifndef RTXHDR_ERR
#define RTXHDR_ERR std::cerr
#endif

namespace {

constexpr int kUnlockCeilingNits = 2000;
// EnsureCuda89() admits only SM 8.9 devices. Carriers such a device can execute
// are patched: SM 8.x CUBINs up to 8.9, and PTX whose target is at most sm_89.
constexpr int kSupportedSm = 89;

constexpr DWORD kProcessAccess = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ |
                                  PROCESS_VM_WRITE | PROCESS_VM_OPERATION;

std::atomic_bool gStop{false};
std::atomic_int gCudaCheck{0};  // 0=unknown, 1=validated, -1=unavailable

void ConfigureConsoleUtf8() {
  // All user-facing literals and Narrow() results are UTF-8. A legacy console
  // code page can therefore render them incorrectly. This affects only console
  // I/O; it does not change process-memory patching or redirected binary data.
  SetConsoleOutputCP(CP_UTF8);
  SetConsoleCP(CP_UTF8);
}

std::string Narrow(const std::wstring& value);

std::string LastErrorText(DWORD error = GetLastError()) {
  std::ostringstream out;
  out << "Win32 error " << error;
  return out.str();
}

std::string Narrow(const std::wstring& value) {
  if (value.empty()) return {};
  const int size = WideCharToMultiByte(CP_UTF8, 0, value.data(),
                                       static_cast<int>(value.size()), nullptr, 0,
                                       nullptr, nullptr);
  if (size <= 0) return "?";
  std::string out(static_cast<std::size_t>(size), '\0');
  WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
                      out.data(), size, nullptr, nullptr);
  return out;
}

std::wstring Lower(std::wstring value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
  return value;
}

std::string Hex(const std::uint8_t* data, std::size_t size) {
  std::ostringstream out;
  out << std::hex << std::setfill('0');
  for (std::size_t i = 0; i < size; ++i) out << std::setw(2) << unsigned(data[i]);
  return out.str();
}

std::string Hex(const std::array<std::uint8_t, 32>& value) {
  return Hex(value.data(), value.size());
}

class Handle {
 public:
  Handle() = default;
  explicit Handle(HANDLE value) : value_(value) {}
  Handle(const Handle&) = delete;
  Handle& operator=(const Handle&) = delete;
  Handle(Handle&& other) noexcept : value_(other.value_) { other.value_ = nullptr; }
  Handle& operator=(Handle&& other) noexcept {
    if (this != &other) {
      reset();
      value_ = other.value_;
      other.value_ = nullptr;
    }
    return *this;
  }
  ~Handle() { reset(); }
  void reset(HANDLE value = nullptr) {
    if (value_ && value_ != INVALID_HANDLE_VALUE) CloseHandle(value_);
    value_ = value;
  }
  HANDLE get() const { return value_; }
  explicit operator bool() const {
    return value_ && value_ != INVALID_HANDLE_VALUE;
  }

 private:
  HANDLE value_ = nullptr;
};

// Self-contained SHA-256 (FIPS 180-4). Carrier identification deliberately
// avoids CNG: BCryptOpenAlgorithmProvider can LoadLibrary a provider while a
// driver thread-attach callback waits inside BCryptGenRandom, which deadlocked
// a fixture once (analysis/proxy_build/rollback_hang_debugger.log).
class Sha256 {
 public:
  void Update(const std::uint8_t* data, std::size_t size) {
    length_ += size;
    while (size) {
      const std::size_t take = std::min(size, buffer_.size() - used_);
      std::memcpy(buffer_.data() + used_, data, take);
      used_ += take;
      data += take;
      size -= take;
      if (used_ == buffer_.size()) {
        Block(buffer_.data());
        used_ = 0;
      }
    }
  }

  std::array<std::uint8_t, 32> Finish() {
    const std::uint64_t bits = length_ * 8;
    buffer_[used_++] = 0x80;
    if (used_ > 56) {
      std::fill(buffer_.begin() + used_, buffer_.end(), std::uint8_t{0});
      Block(buffer_.data());
      used_ = 0;
    }
    std::fill(buffer_.begin() + used_, buffer_.begin() + 56, std::uint8_t{0});
    for (int i = 0; i < 8; ++i) buffer_[56 + i] = std::uint8_t(bits >> (56 - 8 * i));
    Block(buffer_.data());
    std::array<std::uint8_t, 32> digest{};
    for (int i = 0; i < 8; ++i)
      for (int j = 0; j < 4; ++j) digest[4 * i + j] = std::uint8_t(state_[i] >> (24 - 8 * j));
    return digest;
  }

 private:
  static std::uint32_t Rotr(std::uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

  void Block(const std::uint8_t* p) {
    static constexpr std::uint32_t k[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2};
    std::uint32_t w[64];
    for (int i = 0; i < 16; ++i)
      w[i] = std::uint32_t(p[4 * i]) << 24 | std::uint32_t(p[4 * i + 1]) << 16 |
             std::uint32_t(p[4 * i + 2]) << 8 | std::uint32_t(p[4 * i + 3]);
    for (int i = 16; i < 64; ++i) {
      const std::uint32_t s0 = Rotr(w[i - 15], 7) ^ Rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
      const std::uint32_t s1 = Rotr(w[i - 2], 17) ^ Rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
      w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    std::uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];
    std::uint32_t e = state_[4], f = state_[5], g = state_[6], h = state_[7];
    for (int i = 0; i < 64; ++i) {
      const std::uint32_t t1 = h + (Rotr(e, 6) ^ Rotr(e, 11) ^ Rotr(e, 25)) +
                               ((e & f) ^ (~e & g)) + k[i] + w[i];
      const std::uint32_t t2 = (Rotr(a, 2) ^ Rotr(a, 13) ^ Rotr(a, 22)) +
                               ((a & b) ^ (a & c) ^ (b & c));
      h = g;
      g = f;
      f = e;
      e = d + t1;
      d = c;
      c = b;
      b = a;
      a = t1 + t2;
    }
    state_[0] += a;
    state_[1] += b;
    state_[2] += c;
    state_[3] += d;
    state_[4] += e;
    state_[5] += f;
    state_[6] += g;
    state_[7] += h;
  }

  std::array<std::uint32_t, 8> state_ = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                          0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
  std::array<std::uint8_t, 64> buffer_{};
  std::size_t used_ = 0;
  std::uint64_t length_ = 0;
};

std::string Sha256Hex(const std::uint8_t* data, std::size_t size) {
  Sha256 hash;
  hash.Update(data, size);
  return Hex(hash.Finish());
}

constexpr std::array<const wchar_t*, 2> kDriverModules = {L"nvAIHDRx.dll", L"nvwgf2umx.dll"};

bool IsDriverModule(const std::wstring& name) {
  const std::wstring lower = Lower(name);
  for (const auto* module : kDriverModules)
    if (lower == Lower(module)) return true;
  return false;
}

struct ModuleInfo {
  std::wstring name;
  std::wstring path;
  std::uintptr_t base = 0;
  DWORD size = 0;
};

std::vector<ModuleInfo> ModulesForPid(DWORD pid) {
  std::vector<ModuleInfo> result;
  Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid));
  if (!snapshot) return result;
  MODULEENTRY32W entry{};
  entry.dwSize = sizeof(entry);
  if (!Module32FirstW(snapshot.get(), &entry)) return result;
  do {
    if (IsDriverModule(entry.szModule)) {
      ModuleInfo info;
      info.name = entry.szModule;
      info.path = entry.szExePath;
      info.base = reinterpret_cast<std::uintptr_t>(entry.modBaseAddr);
      info.size = entry.modBaseSize;
      result.push_back(std::move(info));
    }
  } while (Module32NextW(snapshot.get(), &entry));
  return result;
}

std::wstring ProcessName(DWORD pid) {
  Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
  if (!snapshot) return L"?";
  PROCESSENTRY32W entry{};
  entry.dwSize = sizeof(entry);
  if (!Process32FirstW(snapshot.get(), &entry)) return L"?";
  do {
    if (entry.th32ProcessID == pid) return entry.szExeFile;
  } while (Process32NextW(snapshot.get(), &entry));
  return L"?";
}

bool ReadRemote(HANDLE process, std::uintptr_t address, void* data, std::size_t size) {
  SIZE_T read = 0;
  return ReadProcessMemory(process, reinterpret_cast<const void*>(address), data, size,
                            &read) && read == size;
}

// Walks every region in the range: pages written once (by this patch, another
// instance or a tool) become private copies with their own protection, so one
// carrier can span several regions.
bool IsRangeReadable(HANDLE process, std::uintptr_t address, std::size_t size) {
  const std::uintptr_t end = address + size;
  if (end < address) return false;
  for (std::uintptr_t cursor = address; cursor < end;) {
    MEMORY_BASIC_INFORMATION info{};
    if (!VirtualQueryEx(process, reinterpret_cast<const void*>(cursor), &info, sizeof(info)))
      return false;
    const auto begin = reinterpret_cast<std::uintptr_t>(info.BaseAddress);
    if (info.State != MEM_COMMIT || cursor < begin || !info.RegionSize ||
        (info.Protect & (PAGE_NOACCESS | PAGE_GUARD)))
      return false;
    cursor = begin + info.RegionSize;
  }
  return true;
}

// A read-only view of a driver file. Carriers are classified from the file
// before any driver module is loaded.
struct MappedFile {
  MappedFile() = default;
  MappedFile(const MappedFile&) = delete;
  MappedFile& operator=(const MappedFile&) = delete;
  ~MappedFile() {
    if (view) UnmapViewOfFile(view);
  }
  Handle file;
  Handle mapping;
  const std::uint8_t* view = nullptr;
  std::size_t size = 0;
};

bool MapReadOnly(const std::wstring& path, MappedFile& out) {
  out.file.reset(CreateFileW(path.c_str(), GENERIC_READ,
                             FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
  LARGE_INTEGER size{};
  if (!out.file || !GetFileSizeEx(out.file.get(), &size) || size.QuadPart <= 0 ||
      size.QuadPart > (std::int64_t{1} << 31))
    return false;
  out.mapping.reset(CreateFileMappingW(out.file.get(), nullptr, PAGE_READONLY, 0, 0, nullptr));
  if (!out.mapping) return false;
  out.view = static_cast<const std::uint8_t*>(
      MapViewOfFile(out.mapping.get(), FILE_MAP_READ, 0, 0, 0));
  out.size = static_cast<std::size_t>(size.QuadPart);
  return out.view != nullptr;
}

std::uint32_t FloatBits(float value) {
  std::uint32_t bits = 0;
  std::memcpy(&bits, &value, sizeof(bits));
  return bits;
}

struct CeilingConstants {
  std::uint32_t tolerance;  // in-gamut upper test, (ceiling + 1 nit) / 1000
  std::uint32_t ceiling;    // final channel clamp, ceiling / 1000
};
constexpr CeilingConstants kOriginalConstants{0x3F8020C5u, 0x3F800000u};  // 1.001, 1.0
constexpr std::uint32_t kLowerBoundBits = 0xBA83126Fu;                    // -0.001

CeilingConstants TargetConstants(int nits) {
  // Same rounding as the validated generators: one double division, one float rounding.
  return {FloatBits(static_cast<float>(static_cast<double>(nits + 1) / 1000.0)),
          FloatBits(static_cast<float>(static_cast<double>(nits) / 1000.0))};
}

enum class CarrierKind { kCubin, kPtx };
enum class CarrierState { kInvalid, kOriginal, kPatched };

struct PatchSite {
  std::uint32_t offset;  // byte offset from the carrier start
  bool tolerance;        // in-gamut test bound; otherwise the final ceiling clamp
};

struct KnownCarrier {
  const char* label;
  const char* original;  // SHA-256 of the unmodified carrier
  const char* patched;   // SHA-256 after the kUnlockCeilingNits patch
};

// Carriers whose patched form passed the real HDR A/B in this project
// (analysis/fixed2000_release.md). Byte-identical in NVIDIA 616.92 through
// 621.14 (the PTX first appears in 621.01). Other carriers are patched only
// when the structural locator accepts them, and the log reports them as
// tier=structural.
static_assert(kUnlockCeilingNits == 2000, "kKnownCarriers lists 2000-nit patched hashes");
constexpr std::array<KnownCarrier, 2> kKnownCarriers = {{
    {"validated sm80 CUBIN", "f08e2619636e181ecf0fddbee78488b6719f47521ccb8595b5fb12fff6a8d6c6",
     "c30752fe8783535691a64ad3eaa46ae5a865a3beb070c66731af0f34a6bd5e28"},
    {"validated PTX", "d41d157c91be935c2a84217bb38686d140bcfde70606f640aeeaba8aa0c56776",
     "972d512e0ae905ea9dca21d4314f02139479b581111d1983aa4ddc6155bb94b5"},
}};

struct Carrier {
  CarrierKind kind = CarrierKind::kCubin;
  std::uintptr_t rva = 0;      // image RVA, or offset inside a bare buffer
  std::size_t size = 0;
  int sm = 0;                  // CUBIN: ELF SM; PTX: .target sm_XX; 0 unknown; -1 arch-specific
  int elfAbi = 0;              // CUBIN ELF OSABI: 0x33 (ABI 7) or 0x41 (ABI 8)
  std::size_t codeOffset = 0;  // CUBIN: .text.truehdr_drtm offset; PTX: entry offset
  std::size_t codeSize = 0;    // CUBIN: .text.truehdr_drtm size
  const std::uint8_t* view = nullptr;  // scanned bytes; valid only while they stay mapped
  bool usable = false;         // executable on kSupportedSm
  CarrierState state = CarrierState::kInvalid;
  std::vector<PatchSite> sites;
  std::string idiom;
  std::string reason;
  std::string sha256;
  const KnownCarrier* known = nullptr;
};

template <typename T>
T LoadLe(const std::uint8_t* p) {
  T value{};
  std::memcpy(&value, p, sizeof(value));
  return value;
}

std::size_t FindText(std::string_view haystack, std::size_t from, std::string_view needle) {
  if (from >= haystack.size() || haystack.size() - from < needle.size())
    return std::string_view::npos;
  const auto begin = haystack.begin() + static_cast<std::ptrdiff_t>(from);
  const auto it = std::search(begin, haystack.end(),
                              std::boyer_moore_horspool_searcher(needle.begin(), needle.end()));
  return it == haystack.end() ? std::string_view::npos
                              : static_cast<std::size_t>(it - haystack.begin());
}

constexpr std::string_view kDrtmText = ".text.truehdr_drtm";
constexpr std::string_view kPtxEntry = ".entry truehdr_drtm(";

struct ElfLayout {
  std::size_t size = 0;
  int sm = 0;
  int abi = 0;
  std::size_t text = 0;
  std::size_t textSize = 0;
  int drtmTexts = 0;
};

// Accepts both CUDA ELF flavors: OSABI 0x33 / ABI 7 (SM in e_flags[0:8], the
// carriers shipped through 621.14) and OSABI 0x41 / ABI 8 (SM in e_flags[8:16],
// produced by CUDA 13 toolchains such as the driver's own JIT).
bool ParseCudaElf(const std::uint8_t* p, std::size_t avail, ElfLayout& layout) {
  if (avail < 64 || std::memcmp(p, "\x7f" "ELF\x02\x01\x01", 7) != 0 ||
      (p[7] != 0x33 && p[7] != 0x41))
    return false;
  const auto phoff = LoadLe<std::uint64_t>(p + 0x20);
  const auto shoff = LoadLe<std::uint64_t>(p + 0x28);
  const auto flags = LoadLe<std::uint32_t>(p + 0x30);
  const auto phentsize = LoadLe<std::uint16_t>(p + 0x36);
  const auto phnum = LoadLe<std::uint16_t>(p + 0x38);
  const auto shentsize = LoadLe<std::uint16_t>(p + 0x3A);
  const auto shnum = LoadLe<std::uint16_t>(p + 0x3C);
  const auto shstrndx = LoadLe<std::uint16_t>(p + 0x3E);
  if (shentsize != 64 || shnum == 0 || shnum > 4096 || shstrndx >= shnum) return false;
  if (shoff > avail || std::uint64_t{shnum} * 64 > avail - shoff) return false;
  std::uint64_t end = shoff + std::uint64_t{shnum} * 64;
  if (phnum) {
    if (phentsize < 56 || phoff > avail ||
        std::uint64_t{phnum} * phentsize > avail - phoff)
      return false;
    end = std::max<std::uint64_t>(end, phoff + std::uint64_t{phnum} * phentsize);
  }
  const std::uint8_t* table = p + shoff;
  const auto strOffset = LoadLe<std::uint64_t>(table + 64 * shstrndx + 0x18);
  const auto strSize = LoadLe<std::uint64_t>(table + 64 * shstrndx + 0x20);
  if (strOffset > avail || strSize > avail - strOffset) return false;
  layout = {};
  for (unsigned i = 0; i < shnum; ++i) {
    const std::uint8_t* header = table + 64 * i;
    const auto name = LoadLe<std::uint32_t>(header);
    const auto type = LoadLe<std::uint32_t>(header + 4);
    const auto offset = LoadLe<std::uint64_t>(header + 0x18);
    const auto size = LoadLe<std::uint64_t>(header + 0x20);
    if (type != 8) {  // SHT_NOBITS occupies no file bytes
      if (offset > avail || size > avail - offset) return false;
      end = std::max<std::uint64_t>(end, offset + size);
    }
    if (name >= strSize) return false;
    const char* text = reinterpret_cast<const char*>(p + strOffset + name);
    const auto room = static_cast<std::size_t>(strSize - name);
    const void* terminator = std::memchr(text, 0, room);
    if (!terminator) return false;
    const std::string_view sectionName(text, static_cast<const char*>(terminator) - text);
    if (sectionName == kDrtmText) {
      ++layout.drtmTexts;
      layout.text = static_cast<std::size_t>(offset);
      layout.textSize = static_cast<std::size_t>(size);
    }
  }
  layout.size = static_cast<std::size_t>(end);
  layout.abi = p[7];
  layout.sm = p[7] == 0x33 ? int(flags & 0xFF) : int((flags >> 8) & 0xFF);
  return true;
}

int PtxTargetSm(std::string_view header) {
  const std::size_t target = FindText(header, 0, ".target sm_");
  if (target == std::string_view::npos) return 0;
  int sm = 0;
  std::size_t i = target + 11;
  for (; i < header.size() && i < target + 15 && header[i] >= '0' && header[i] <= '9'; ++i)
    sm = sm * 10 + (header[i] - '0');
  if (i < header.size() && std::isalpha(static_cast<unsigned char>(header[i]))) return -1;
  return sm;
}

bool IsPtxTextByte(std::uint8_t b) { return b == '\t' || b == '\n' || b == '\r' || (b >= 0x20 && b < 0x7F); }

// Finds every truehdr_drtm carrier inside one contiguous byte range.
void ScanSpan(const std::uint8_t* data, std::size_t size, std::uintptr_t rva,
              std::vector<Carrier>& out) {
  const std::string_view text(reinterpret_cast<const char*>(data), size);
  for (std::size_t pos = 0; pos + 8 <= size;) {
    const void* hit = std::memchr(data + pos, 0x7F, size - pos);
    if (!hit) break;
    const auto at = static_cast<std::size_t>(static_cast<const std::uint8_t*>(hit) - data);
    pos = at + 1;
    if (size - at < 8 || std::memcmp(data + at + 1, "ELF\x02\x01\x01", 6) != 0 ||
        (data[at + 7] != 0x33 && data[at + 7] != 0x41))
      continue;
    ElfLayout layout;
    Carrier carrier;
    carrier.kind = CarrierKind::kCubin;
    carrier.rva = rva + at;
    carrier.view = data + at;
    carrier.elfAbi = data[at + 7];
    if (ParseCudaElf(data + at, size - at, layout)) {
      if (layout.drtmTexts == 0) continue;
      carrier.size = layout.size;
      carrier.sm = layout.sm;
      carrier.codeOffset = layout.text;
      carrier.codeSize = layout.textSize;
      if (layout.drtmTexts != 1) carrier.reason = "several .text.truehdr_drtm sections";
      out.push_back(carrier);
      pos = at + layout.size;
      continue;
    }
    // A CUDA ELF this parser cannot read must not hide a kernel: refuse if it
    // names .text.truehdr_drtm before the next ELF header.
    std::size_t limit = FindText(text, at + 4, "\x7f" "ELF");
    if (limit == std::string_view::npos) limit = size;
    if (FindText(text.substr(0, limit), at, kDrtmText) != std::string_view::npos) {
      carrier.size = limit - at;
      carrier.reason = "unparseable CUDA ELF containing .text.truehdr_drtm";
      out.push_back(carrier);
    }
  }
  for (std::size_t from = 0;;) {
    const std::size_t entry = FindText(text, from, kPtxEntry);
    if (entry == std::string_view::npos) break;
    std::size_t start = entry;
    const std::size_t floor = entry > (std::size_t{16} << 20) ? entry - (std::size_t{16} << 20) : 0;
    while (start > floor && IsPtxTextByte(data[start - 1])) --start;
    Carrier carrier;
    carrier.kind = CarrierKind::kPtx;
    carrier.rva = rva + start;
    carrier.view = data + start;
    carrier.codeOffset = entry - start;
    carrier.sm = PtxTargetSm(text.substr(start, entry - start));
    const void* nul = std::memchr(data + entry, 0, size - entry);
    if (!nul) {
      carrier.size = size - start;
      carrier.reason = "unterminated PTX module";
      out.push_back(carrier);
      break;
    }
    const auto end = static_cast<std::size_t>(static_cast<const std::uint8_t*>(nul) - data) + 1;
    carrier.size = end - start;
    out.push_back(carrier);
    from = end;
  }
}

// Scans every initialized, readable, non-executable section of a PE image.
// fileLayout selects raw file offsets (a mapped file) or RVAs (a loaded image).
bool ScanImage(const std::uint8_t* image, std::size_t size, bool fileLayout,
               std::vector<Carrier>& carriers, std::string& error) {
  carriers.clear();
  IMAGE_DOS_HEADER dos{};
  IMAGE_NT_HEADERS64 nt{};
  if (size < sizeof(dos)) {
    error = "file is too small for a PE image";
    return false;
  }
  std::memcpy(&dos, image, sizeof(dos));
  if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0 ||
      static_cast<std::size_t>(dos.e_lfanew) > size - sizeof(nt)) {
    error = "not a PE image";
    return false;
  }
  std::memcpy(&nt, image + dos.e_lfanew, sizeof(nt));
  if (nt.Signature != IMAGE_NT_SIGNATURE || nt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
      nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
    error = "not an x64 PE image";
    return false;
  }
  const std::size_t table = static_cast<std::size_t>(dos.e_lfanew) +
                            offsetof(IMAGE_NT_HEADERS64, OptionalHeader) +
                            nt.FileHeader.SizeOfOptionalHeader;
  const std::size_t count = nt.FileHeader.NumberOfSections;
  if (table > size || count * sizeof(IMAGE_SECTION_HEADER) > size - table) {
    error = "truncated PE section table";
    return false;
  }
  for (std::size_t i = 0; i < count; ++i) {
    IMAGE_SECTION_HEADER section{};
    std::memcpy(&section, image + table + i * sizeof(section), sizeof(section));
    const DWORD flags = section.Characteristics;
    if (!(flags & IMAGE_SCN_CNT_INITIALIZED_DATA) || !(flags & IMAGE_SCN_MEM_READ) ||
        (flags & IMAGE_SCN_MEM_EXECUTE))
      continue;
    std::size_t begin = fileLayout ? section.PointerToRawData : section.VirtualAddress;
    std::size_t length = section.SizeOfRawData;
    if (section.Misc.VirtualSize) length = std::min<std::size_t>(length, section.Misc.VirtualSize);
    if (!length || begin >= size) continue;
    length = std::min(length, size - begin);
    ScanSpan(image + begin, length, section.VirtualAddress, carriers);
  }
  return true;
}

struct SassWord {
  std::uint64_t lo = 0;
  std::uint64_t hi = 0;
  unsigned Op() const { return unsigned(lo & 0xFFF); }
  unsigned Guard() const { return unsigned((lo >> 12) & 0xF); }
  unsigned Ra() const { return unsigned((lo >> 24) & 0xFF); }
  std::uint32_t Imm() const { return std::uint32_t(lo >> 32); }
  unsigned Cmp() const { return unsigned((hi >> 12) & 0xF); }
  unsigned Pd() const { return unsigned((hi >> 17) & 0x7); }
  unsigned Pd2() const { return unsigned((hi >> 20) & 0x7); }
  unsigned Pp() const { return unsigned((hi >> 23) & 0xF); }
  bool ImmediateForm() const { return (Op() & 0xF00) == 0x800; }
};

// Volta+ 128-bit SASS (verified on sm75, sm80, sm89, sm120 and sm121 builds):
// op lo[0:12], guard lo[12:16], Ra lo[24:32], imm32 lo[32:64]; FSETP compare
// hi[12:16], Pd hi[17:20], Pd2 hi[20:23]; FSETP/FSEL/FMNMX predicate hi[23:27]
// (bit 3 negates; FMNMX with PT selects the minimum).
constexpr unsigned kOpFsetp = 0x80B, kOpFsel = 0x808, kOpFmnmx = 0x809;
constexpr unsigned kCmpGe = 6, kPredTrue = 7, kPredNegate = 8;

// The Oklab gamut mapping has three paths (full frame, left and right split).
// Each tests the three candidate channels against [-0.001, tolerance] before
// and inside its chroma bisection loop (18 tolerance immediates), then clamps
// each candidate to the ceiling: FSETP.GE + FSEL !P (sm75/sm80) or FMNMX (newer
// compilers). Every other use of 1.0 in the kernel is left alone.
bool LocateSass(const std::uint8_t* elf, std::size_t text, std::size_t textSize,
                const CeilingConstants& k, std::vector<PatchSite>& sites,
                std::string& idiom, std::string& why) {
  sites.clear();
  if (textSize == 0 || textSize % 16) {
    why = "kernel code size is not a multiple of 16 bytes";
    return false;
  }
  const std::size_t count = textSize / 16;
  std::vector<SassWord> code(count);
  for (std::size_t i = 0; i < count; ++i) {
    std::memcpy(&code[i].lo, elf + text + 16 * i, 8);
    std::memcpy(&code[i].hi, elf + text + 16 * i + 8, 8);
  }
  std::vector<std::size_t> tests;
  for (std::size_t i = 0; i < count; ++i) {
    if (!code[i].ImmediateForm() || code[i].Imm() != k.tolerance) continue;
    if (code[i].Op() != kOpFsetp) {
      why = "the gamut tolerance constant is used by a non-FSETP instruction";
      return false;
    }
    tests.push_back(i);
  }
  if (tests.size() != 18) {
    why = "expected 18 gamut tolerance tests, found " + std::to_string(tests.size());
    return false;
  }
  for (const auto t : tests) {
    if (code[t].Guard() != kPredTrue) {
      why = "a gamut tolerance test is predicated";
      return false;
    }
    bool partner = false;
    for (std::size_t j = t >= 8 ? t - 8 : 0; j <= std::min(count - 1, t + 8) && !partner; ++j)
      partner = code[j].Op() == kOpFsetp && code[j].Imm() == kLowerBoundBits &&
                code[j].Ra() == code[t].Ra();
    if (!partner) {
      why = "a gamut tolerance test lacks its -0.001 lower-bound test";
      return false;
    }
  }
  std::vector<std::vector<std::size_t>> groups{{tests.front()}};
  for (std::size_t i = 1; i < tests.size(); ++i) {
    if (tests[i] - tests[i - 1] <= 8) groups.back().push_back(tests[i]);
    else groups.push_back({tests[i]});
  }
  if (groups.size() != 6) {
    why = "expected 6 three-channel gamut test groups, found " + std::to_string(groups.size());
    return false;
  }
  for (const auto& group : groups) {
    std::set<unsigned> registers;
    for (const auto i : group) registers.insert(code[i].Ra());
    if (group.size() != 3 || registers.size() != 3) {
      why = "a gamut test group does not cover three distinct channels";
      return false;
    }
  }
  for (const auto t : tests) sites.push_back({std::uint32_t(text + 16 * t + 4), true});
  int pairs = 0;
  int minima = 0;
  for (std::size_t path = 0; path < 3; ++path) {
    const auto& first = groups[2 * path];
    const auto& second = groups[2 * path + 1];
    if (second.front() - first.back() > 160) {
      why = "the two gamut tests of a path are too far apart";
      return false;
    }
    std::set<unsigned> candidates;
    for (const auto i : first) candidates.insert(code[i].Ra());
    std::set<unsigned> tested = candidates;
    for (const auto i : second) tested.insert(code[i].Ra());
    const std::size_t begin = second.back() + 1;
    const std::size_t end = std::min(count, begin + 64);
    std::map<unsigned, std::vector<std::vector<std::size_t>>> clamps;
    std::set<std::size_t> pairedSelects;
    for (std::size_t j = begin; j < end; ++j) {
      const auto& word = code[j];
      if (!word.ImmediateForm() || word.Imm() != k.ceiling || !tested.count(word.Ra())) continue;
      if (word.Op() == kOpFmnmx) {
        if (word.Pp() != kPredTrue || word.Guard() != kPredTrue) {
          why = "a ceiling FMNMX is not an unconditional minimum";
          return false;
        }
        clamps[word.Ra()].push_back({j});
        ++minima;
      } else if (word.Op() == kOpFsetp) {
        if (word.Cmp() != kCmpGe || word.Pd2() != kPredTrue || word.Pp() != kPredTrue ||
            word.Guard() != kPredTrue) {
          why = "a ceiling comparison is not FSETP.GE.AND Pn, PT, c, ceiling, PT";
          return false;
        }
        std::vector<std::size_t> selects;
        for (std::size_t s = j + 1; s < std::min(end, j + 25); ++s) {
          const auto& select = code[s];
          if (select.Op() == kOpFsel && select.Imm() == k.ceiling && select.Ra() == word.Ra() &&
              select.Pp() == (kPredNegate | word.Pd()) && select.Guard() == kPredTrue)
            selects.push_back(s);
        }
        if (selects.size() != 1) {
          why = "a ceiling comparison has no unique FSEL partner";
          return false;
        }
        pairedSelects.insert(selects.front());
        clamps[word.Ra()].push_back({j, selects.front()});
        ++pairs;
      }
    }
    for (std::size_t j = begin; j < end; ++j) {
      const auto& word = code[j];
      if (word.Op() == kOpFsel && word.Imm() == k.ceiling && tested.count(word.Ra()) &&
          !pairedSelects.count(j)) {
        why = "an FSEL with the ceiling constant is not part of a recognized clamp";
        return false;
      }
    }
    if (clamps.size() != 3) {
      why = "expected three clamped channels per path, found " + std::to_string(clamps.size());
      return false;
    }
    for (const auto& [reg, entries] : clamps) {
      if (entries.size() != 1 || !candidates.count(reg)) {
        why = "a channel is clamped twice or is not a gamut candidate";
        return false;
      }
      for (const auto i : entries.front()) sites.push_back({std::uint32_t(text + 16 * i + 4), false});
    }
  }
  std::sort(sites.begin(), sites.end(),
            [](const PatchSite& a, const PatchSite& b) { return a.offset < b.offset; });
  idiom = pairs && !minima ? "FSETP+FSEL" : minima && !pairs ? "FMNMX" : "mixed";
  return true;
}

std::string PtxLiteral(std::uint32_t bits) {
  char text[11]{};
  std::snprintf(text, sizeof(text), "0f%08X", static_cast<unsigned int>(bits));
  return text;
}

struct PtxStatement {
  std::string_view opcode;
  bool guarded = false;
  std::vector<std::pair<std::string_view, std::size_t>> operands;  // text, carrier offset
};

bool ParsePtxStatement(std::string_view carrier, std::size_t begin, std::size_t end,
                       PtxStatement& out) {
  const auto space = [](char c) { return c == ' ' || c == '\t' || c == '\r'; };
  std::size_t i = begin;
  while (i < end && space(carrier[i])) ++i;
  if (i >= end || carrier[i] == '/') return false;
  const auto token = [&]() {
    const std::size_t start = i;
    while (i < end && !space(carrier[i])) ++i;
    const auto value = carrier.substr(start, i - start);
    while (i < end && space(carrier[i])) ++i;
    return value;
  };
  out = {};
  std::string_view first = token();
  if (!first.empty() && first.front() == '@') {
    out.guarded = true;
    first = token();
  }
  out.opcode = first;
  const std::size_t semicolon = carrier.find(';', i);
  if (semicolon == std::string_view::npos || semicolon >= end) return false;
  std::size_t start = i;
  for (std::size_t j = i; j <= semicolon; ++j) {
    if (j != semicolon && carrier[j] != ',') continue;
    std::size_t a = start;
    std::size_t b = j;
    while (a < b && space(carrier[a])) ++a;
    while (b > a && space(carrier[b - 1])) --b;
    out.operands.emplace_back(carrier.substr(a, b - a), a);
    start = j + 1;
  }
  return true;
}

// PTX form of the same structure: 18 "setp.le.f32 %p, %fX, tolerance" tests on
// nine candidate registers (each also tested against -0.001), and one ceiling
// clamp per candidate, "setp.ge.f32 %pA, %fX, ceiling" + "selp.f32 %fY,
// ceiling, %fX, %pA" or "min.f32 %fY, %fX, ceiling". The kernel has other
// clamps to 1.0 (chroma and later output stages); those are not candidates.
bool LocatePtx(const std::uint8_t* data, std::size_t size, std::size_t entry,
               const CeilingConstants& k, std::vector<PatchSite>& sites, std::string& idiom,
               std::string& why) {
  sites.clear();
  const std::string_view carrier(reinterpret_cast<const char*>(data), size);
  std::size_t bodyEnd = FindText(carrier, entry + kPtxEntry.size(), ".entry ");
  if (bodyEnd == std::string_view::npos) bodyEnd = size;
  const std::string tolerance = PtxLiteral(k.tolerance);
  const std::string ceiling = PtxLiteral(k.ceiling);
  const std::string lower = PtxLiteral(kLowerBoundBits);
  std::size_t occurrences = 0;
  for (std::size_t at = FindText(carrier, entry, tolerance); at < bodyEnd;
       at = FindText(carrier, at + 1, tolerance))
    ++occurrences;
  std::vector<PtxStatement> statements;
  for (std::size_t begin = entry; begin < bodyEnd;) {
    std::size_t end = carrier.find('\n', begin);
    if (end == std::string_view::npos || end > bodyEnd) end = bodyEnd;
    PtxStatement statement;
    if (ParsePtxStatement(carrier, begin, end, statement)) statements.push_back(std::move(statement));
    begin = end + 1;
  }
  std::vector<std::size_t> tests;
  std::set<std::string_view> candidates;
  for (const auto& s : statements) {
    for (std::size_t o = 0; o < s.operands.size(); ++o) {
      if (s.operands[o].first != tolerance) continue;
      if (s.guarded || s.opcode != "setp.le.f32" || s.operands.size() != 3 || o != 2 ||
          s.operands[0].first.substr(0, 2) != "%p" || s.operands[1].first.substr(0, 2) != "%f") {
        why = "the gamut tolerance literal is used outside setp.le.f32 %p, %f, literal";
        return false;
      }
      candidates.insert(s.operands[1].first);
      tests.push_back(s.operands[2].second);
    }
  }
  if (occurrences != 18 || tests.size() != 18) {
    why = "expected 18 gamut tolerance tests, found " + std::to_string(tests.size()) + " of " +
          std::to_string(occurrences) + " literals";
    return false;
  }
  if (candidates.size() != 9) {
    why = "expected 9 gamut candidate registers, found " + std::to_string(candidates.size());
    return false;
  }
  for (const auto& candidate : candidates) {
    const bool lowerBound = std::any_of(statements.begin(), statements.end(), [&](const auto& s) {
      return !s.guarded && s.opcode == "setp.ge.f32" && s.operands.size() == 3 &&
             s.operands[1].first == candidate && s.operands[2].first == lower;
    });
    if (!lowerBound) {
      why = "a gamut candidate lacks its -0.001 lower-bound test";
      return false;
    }
  }
  std::map<std::string_view, std::vector<std::vector<std::size_t>>> clamps;
  int pairs = 0;
  int minima = 0;
  for (const auto& s : statements) {
    if (s.guarded || s.operands.size() != 3 || s.operands[2].first != ceiling ||
        !candidates.count(s.operands[1].first))
      continue;
    if (s.opcode == "setp.ge.f32") {
      const auto predicate = s.operands[0].first;
      const auto value = s.operands[1].first;
      std::vector<std::size_t> selects;
      for (const auto& select : statements) {
        if (!select.guarded && select.opcode == "selp.f32" && select.operands.size() == 4 &&
            select.operands[1].first == ceiling && select.operands[2].first == value &&
            select.operands[3].first == predicate)
          selects.push_back(select.operands[1].second);
      }
      if (selects.size() != 1) {
        why = "a ceiling comparison has no unique selp partner";
        return false;
      }
      clamps[value].push_back({s.operands[2].second, selects.front()});
      ++pairs;
    } else if (s.opcode == "min.f32") {
      clamps[s.operands[1].first].push_back({s.operands[2].second});
      ++minima;
    }
  }
  if (clamps.size() != candidates.size()) {
    why = "expected one ceiling clamp per candidate, found " + std::to_string(clamps.size());
    return false;
  }
  for (const auto& [value, entries] : clamps) {
    if (entries.size() != 1) {
      why = "a gamut candidate is clamped to the ceiling more than once";
      return false;
    }
    for (const auto offset : entries.front()) sites.push_back({std::uint32_t(offset), false});
  }
  for (const auto offset : tests) sites.push_back({std::uint32_t(offset), true});
  std::sort(sites.begin(), sites.end(),
            [](const PatchSite& a, const PatchSite& b) { return a.offset < b.offset; });
  idiom = pairs && !minima ? "setp+selp" : minima && !pairs ? "min" : "mixed";
  return true;
}

bool UsableOn(const Carrier& carrier, int deviceSm) {
  if (carrier.sm == 0) return true;  // unknown target: treat as relevant so it can reject
  if (carrier.sm < 0) return false;  // architecture-specific PTX target
  if (carrier.kind == CarrierKind::kPtx) return carrier.sm <= deviceSm;
  return carrier.sm / 10 == deviceSm / 10 && carrier.sm <= deviceSm;
}

// Classifies a scanned carrier as original, patched to peakNits, or invalid.
// carrier.view must still be mapped.
void ClassifyCarrier(Carrier& carrier, int peakNits) {
  carrier.sha256 = Sha256Hex(carrier.view, carrier.size);
  if (!carrier.reason.empty()) {
    carrier.state = CarrierState::kInvalid;
    return;
  }
  const auto locate = [&](const CeilingConstants& k, std::string& why) {
    return carrier.kind == CarrierKind::kCubin
               ? LocateSass(carrier.view, carrier.codeOffset, carrier.codeSize, k, carrier.sites,
                            carrier.idiom, why)
               : LocatePtx(carrier.view, carrier.size, carrier.codeOffset, k, carrier.sites,
                           carrier.idiom, why);
  };
  std::string why;
  std::string ignored;
  if (locate(kOriginalConstants, why)) {
    carrier.state = CarrierState::kOriginal;
  } else if (locate(TargetConstants(peakNits), ignored)) {
    carrier.state = CarrierState::kPatched;
  } else {
    carrier.state = CarrierState::kInvalid;
    carrier.reason = why;
    carrier.sites.clear();
    carrier.idiom.clear();
  }
  carrier.known = nullptr;
  for (const auto& known : kKnownCarriers) {
    if (carrier.state != CarrierState::kInvalid &&
        carrier.sha256 == (carrier.state == CarrierState::kPatched ? known.patched : known.original))
      carrier.known = &known;
  }
}

// Returns the patched copy of an original carrier; only the located immediates change.
std::optional<std::vector<std::uint8_t>> BuildPatchedCarrier(const Carrier& carrier,
                                                             const std::uint8_t* original,
                                                             int peakNits) {
  if (carrier.state != CarrierState::kOriginal || carrier.sites.empty()) return std::nullopt;
  std::vector<std::uint8_t> bytes(original, original + carrier.size);
  const auto target = TargetConstants(peakNits);
  for (const auto& site : carrier.sites) {
    const std::uint32_t before = site.tolerance ? kOriginalConstants.tolerance : kOriginalConstants.ceiling;
    const std::uint32_t after = site.tolerance ? target.tolerance : target.ceiling;
    if (carrier.kind == CarrierKind::kCubin) {
      if (site.offset > bytes.size() || bytes.size() - site.offset < 4) return std::nullopt;
      if (LoadLe<std::uint32_t>(bytes.data() + site.offset) != before) return std::nullopt;
      std::memcpy(bytes.data() + site.offset, &after, 4);
    } else {
      const std::string old = PtxLiteral(before);
      const std::string replacement = PtxLiteral(after);
      if (site.offset > bytes.size() || bytes.size() - site.offset < old.size() ||
          std::memcmp(bytes.data() + site.offset, old.data(), old.size()) != 0)
        return std::nullopt;
      std::memcpy(bytes.data() + site.offset, replacement.data(), replacement.size());
    }
  }
  return bytes;
}

std::string DescribeCarrier(const Carrier& carrier) {
  std::ostringstream out;
  if (carrier.kind == CarrierKind::kCubin) {
    out << "CUBIN sm" << carrier.sm << " (ELF OSABI 0x" << std::hex << carrier.elfAbi << std::dec
        << ')';
  } else {
    out << "PTX target " << (carrier.sm > 0 ? "sm_" + std::to_string(carrier.sm) : "unknown");
  }
  out << " rva=0x" << std::hex << carrier.rva << std::dec << " size=" << carrier.size;
  if (!carrier.sha256.empty()) out << " sha256=" << carrier.sha256.substr(0, 16);
  if (carrier.state == CarrierState::kInvalid) {
    out << " state=invalid reason=\"" << carrier.reason << '"';
  } else {
    const auto tolerance = std::count_if(carrier.sites.begin(), carrier.sites.end(),
                                         [](const PatchSite& s) { return s.tolerance; });
    out << " state=" << (carrier.state == CarrierState::kOriginal ? "original" : "patched")
        << " sites=" << carrier.sites.size() << " (" << tolerance << " tolerance + "
        << carrier.sites.size() - tolerance << " ceiling, " << carrier.idiom << ") tier="
        << (carrier.known ? "known" : "structural");
  }
  if (!carrier.usable) out << "; not executable on SM 8.9, left unchanged";
  return out.str();
}

class SuspendedThreads {
 public:
  explicit SuspendedThreads(DWORD pid) : pid_(pid) {}
  SuspendedThreads(const SuspendedThreads&) = delete;
  ~SuspendedThreads() {
    for (auto it = handles_.rbegin(); it != handles_.rend(); ++it) {
      if (ResumeThread(it->get()) == static_cast<DWORD>(-1)) {
        RTXHDR_ERR << "Failed to resume thread: " << LastErrorText() << "\n";
      }
    }
  }
  bool SuspendAll() {
    Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
    if (!snapshot) {
      RTXHDR_ERR << "Failed to enumerate threads: " << LastErrorText() << "\n";
      return false;
    }
    THREADENTRY32 entry{};
    entry.dwSize = sizeof(entry);
    if (!Thread32First(snapshot.get(), &entry)) {
      RTXHDR_ERR << "Failed to read the thread list: " << LastErrorText() << "\n";
      return false;
    }
    do {
      if (entry.th32OwnerProcessID != pid_) continue;
      Handle thread(OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION,
                               FALSE, entry.th32ThreadID));
      if (!thread) {
        RTXHDR_ERR << "Failed to open target thread " << entry.th32ThreadID << ": "
                  << LastErrorText() << "\n";
        return false;
      }
      if (SuspendThread(thread.get()) == static_cast<DWORD>(-1)) {
        RTXHDR_ERR << "Failed to suspend target thread " << entry.th32ThreadID << ": "
                  << LastErrorText() << "\n";
        return false;
      }
      handles_.push_back(std::move(thread));
    } while (Thread32Next(snapshot.get(), &entry));
    if (handles_.empty()) {
      RTXHDR_ERR << "The target process has no suspendable threads\n";
      return false;
    }
    return true;
  }

 private:
  DWORD pid_;
  std::vector<Handle> handles_;
};

bool WriteRemote(HANDLE process, DWORD pid, std::uintptr_t address,
                 const std::vector<std::uint8_t>& oldBytes,
                 const std::vector<std::uint8_t>& newBytes, bool debugEventStopped = false) {
  if (oldBytes.size() != newBytes.size() || oldBytes.empty()) return false;
  // Allocate all readback storage before changing the target's page protection.
  std::vector<std::uint8_t> stable(oldBytes.size());
  std::vector<std::uint8_t> check(newBytes.size());
  SuspendedThreads suspended(pid);
  if (!debugEventStopped && !suspended.SuspendAll()) return false;

  // Recheck after suspension: the caller's read occurred before thread quiescence,
  // so a concurrent loader must not be overwritten with a stale snapshot.
  if (!ReadRemote(process, address, stable.data(), stable.size()) || stable != oldBytes) {
    RTXHDR_ERR << "Code source changed after threads were suspended; overwrite refused\n";
    return false;
  }

  DWORD previousProtection = 0;
  if (!VirtualProtectEx(process, reinterpret_cast<void*>(address), newBytes.size(),
                        PAGE_EXECUTE_READWRITE, &previousProtection)) {
    RTXHDR_ERR << "Failed to change page protection: " << LastErrorText() << "\n";
    return false;
  }
  bool success = false;
  SIZE_T written = 0;
  const BOOL writeOk = WriteProcessMemory(process, reinterpret_cast<void*>(address),
                                          newBytes.data(), newBytes.size(), &written);
  const DWORD writeError = writeOk ? ERROR_PARTIAL_COPY : GetLastError();
  if (writeOk && written == newBytes.size()) {
    const BOOL flushed = FlushInstructionCache(process, reinterpret_cast<void*>(address),
                                                newBytes.size());
    if (!flushed) RTXHDR_ERR << "Instruction-cache flush failed; rolling back: " << LastErrorText() << "\n";
    success = ReadRemote(process, address, check.data(), check.size()) && check == newBytes;
    if (!success) RTXHDR_ERR << "Write readback verification failed; rolling back\n";
    success = success && flushed;
  } else {
    RTXHDR_ERR << "Failed to write process memory: " << LastErrorText(writeError) << " (written=" << written
              << ")\n";
  }
  DWORD ignored = 0;
  if (success) {
    if (VirtualProtectEx(process, reinterpret_cast<void*>(address), newBytes.size(),
                         previousProtection, &ignored)) return true;
    RTXHDR_ERR << "Failed to restore page protection; rolling back: " << LastErrorText() << "\n";
  }

  // A failed protection restore may have changed some pages. Re-establish write
  // access, roll back the bytes, then retry the original protection in all cases.
  if (!VirtualProtectEx(process, reinterpret_cast<void*>(address), oldBytes.size(),
                        PAGE_EXECUTE_READWRITE, &ignored)) {
    RTXHDR_ERR << "Failed to make pages writable during rollback: " << LastErrorText() << "\n";
  }
  SIZE_T restored = 0;
  const BOOL rollbackWrite = WriteProcessMemory(process, reinterpret_cast<void*>(address),
                                                oldBytes.data(), oldBytes.size(), &restored);
  const DWORD rollbackError = rollbackWrite ? ERROR_PARTIAL_COPY : GetLastError();
  if (!rollbackWrite || restored != oldBytes.size()) {
    RTXHDR_ERR << "Rollback write failed: " << LastErrorText(rollbackError)
              << " (written=" << restored << ")\n";
  }
  const BOOL rollbackFlushed = FlushInstructionCache(process, reinterpret_cast<void*>(address),
                                                      oldBytes.size());
  if (!rollbackFlushed) RTXHDR_ERR << "Rollback instruction-cache flush failed: " << LastErrorText() << "\n";
  const bool bytesRestored = ReadRemote(process, address, check.data(), check.size()) &&
                              check == oldBytes;
  const BOOL protectionRestored = VirtualProtectEx(process, reinterpret_cast<void*>(address),
                                                    oldBytes.size(), previousProtection, &ignored);
  const DWORD protectionError = protectionRestored ? ERROR_SUCCESS : GetLastError();
  if (!bytesRestored) RTXHDR_ERR << "Rollback readback did not confirm original bytes; target memory state is unknown\n";
  if (!protectionRestored)
    RTXHDR_ERR << "Failed to restore page protection after rollback: " << LastErrorText(protectionError) << "\n";
  if (bytesRestored && protectionRestored && rollbackFlushed)
    RTXHDR_ERR << "Rollback confirmed by readback; original bytes and page protection restored\n";
  return false;
}

struct CarrierWrite {
  std::string label;
  std::uintptr_t address = 0;
  std::vector<std::uint8_t> before;
  std::vector<std::uint8_t> after;
};

// All-or-nothing over every carrier of every module: each region is rechecked
// after thread suspension, written with readback, and earlier regions are
// rolled back if a later one fails.
bool ApplyCarrierWrites(HANDLE process, DWORD pid, const std::vector<CarrierWrite>& writes,
                        bool debugEventStopped = false) {
  SuspendedThreads suspended(pid);
  if (!debugEventStopped && !suspended.SuspendAll()) return false;
  for (const auto& write : writes) {
    std::vector<std::uint8_t> current(write.before.size());
    if (!ReadRemote(process, write.address, current.data(), current.size()) ||
        current != write.before) {
      RTXHDR_ERR << write.label << " changed after threads were suspended; no carrier was written\n";
      return false;
    }
  }
  std::size_t done = 0;
  for (; done < writes.size(); ++done) {
    const auto& write = writes[done];
    if (!WriteRemote(process, pid, write.address, write.before, write.after, true)) break;
  }
  if (done == writes.size()) return true;
  RTXHDR_ERR << writes[done].label << " update failed; rolling back " << done
             << " carrier(s) written earlier in this transaction\n";
  for (std::size_t i = done; i-- > 0;) {
    if (!WriteRemote(process, pid, writes[i].address, writes[i].after, writes[i].before, true))
      RTXHDR_ERR << writes[i].label << " rollback failed; complete restoration cannot be confirmed\n";
  }
  return false;
}

struct CudaFns {
  using Result = int;
  using Init = Result(__stdcall*)(unsigned int);
  using GetCount = Result(__stdcall*)(int*);
  using GetDevice = Result(__stdcall*)(int*, int);
  using GetAttribute = Result(__stdcall*)(int*, int, int);
  using GetLuid = Result(__stdcall*)(char*, unsigned int*, int);
  HMODULE module = nullptr;
  ~CudaFns() {
    if (module) FreeLibrary(module);
  }
  Init init = nullptr;
  GetCount getCount = nullptr;
  GetDevice getDevice = nullptr;
  GetAttribute getAttribute = nullptr;
  GetLuid getLuid = nullptr;
};

bool ValidateCuda89() {
  CudaFns cuda;
  cuda.module = LoadLibraryExW(L"nvcuda.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
  if (!cuda.module) {
    RTXHDR_ERR << "Failed to load nvcuda.dll; write refused\n";
    return false;
  }
  cuda.init = reinterpret_cast<CudaFns::Init>(GetProcAddress(cuda.module, "cuInit"));
  cuda.getCount = reinterpret_cast<CudaFns::GetCount>(GetProcAddress(
      cuda.module, "cuDeviceGetCount"));
  cuda.getDevice = reinterpret_cast<CudaFns::GetDevice>(GetProcAddress(
      cuda.module, "cuDeviceGet"));
  cuda.getAttribute = reinterpret_cast<CudaFns::GetAttribute>(GetProcAddress(
      cuda.module, "cuDeviceGetAttribute"));
  cuda.getLuid = reinterpret_cast<CudaFns::GetLuid>(GetProcAddress(
      cuda.module, "cuDeviceGetLuid"));
  if (!cuda.init || !cuda.getCount || !cuda.getDevice || !cuda.getAttribute ||
      !cuda.getLuid || cuda.init(0) != 0) {
    RTXHDR_ERR << "CUDA Driver API is unavailable; write refused\n";
    return false;
  }
  int count = 0;
  if (cuda.getCount(&count) != 0) {
    RTXHDR_ERR << "Failed to enumerate CUDA devices; write refused\n";
    return false;
  }
  bool matched = false;
  for (int i = 0; i < count; ++i) {
    int device = 0;
    int major = 0;
    int minor = 0;
    if (cuda.getDevice(&device, i) != 0 ||
        cuda.getAttribute(&major, 75, device) != 0 ||
        cuda.getAttribute(&minor, 76, device) != 0)
      continue;
    char luid[8]{};
    unsigned int nodeMask = 0;
    const bool luidOk = cuda.getLuid(luid, &nodeMask, device) == 0;
    RTXHDR_OUT << "CUDA device " << i << ": capability " << major << '.' << minor;
    if (luidOk) RTXHDR_OUT << ", LUID=" << Hex(reinterpret_cast<std::uint8_t*>(luid), 8)
                           << ", nodeMask=" << nodeMask;
    RTXHDR_OUT << "\n";
    if (major == 8 && minor == 9 && luidOk) matched = true;
  }
  if (!matched) {
    RTXHDR_ERR << "No CUDA device with capability 8.9 and a readable LUID was found; write refused\n";
    return false;
  }
  return true;
}

bool EnsureCuda89() {
  const int cached = gCudaCheck.load();
  if (cached == 1) return true;
  if (cached == -1) return false;
  const bool ok = ValidateCuda89();
  gCudaCheck.store(ok ? 1 : -1);
  return ok;
}

bool IsSelf(DWORD pid) { return pid == GetCurrentProcessId(); }

bool OpenTarget(DWORD pid, Handle& process) {
  if (IsSelf(pid)) {
    RTXHDR_ERR << "Refusing to operate on the current process\n";
    return false;
  }
  process.reset(OpenProcess(kProcessAccess, FALSE, pid));
  if (!process) {
    RTXHDR_ERR << "Failed to open target process: " << LastErrorText() << "\n";
    return false;
  }
  return true;
}

bool ProcessModules(DWORD pid, std::vector<ModuleInfo>& modules) {
  modules = ModulesForPid(pid);
  if (modules.empty()) return false;
  return true;
}

}  // namespace
