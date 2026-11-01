#pragma once
// Shared, version-locked kernel validation and patch transaction.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#include <tlhelp32.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <cwctype>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "unlock_kernel.h"
#include "unlock_ptx.h"

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "user32.lib")

#ifndef RTXHDR_OUT
#define RTXHDR_OUT std::cout
#endif
#ifndef RTXHDR_ERR
#define RTXHDR_ERR std::cerr
#endif

namespace {

constexpr int kUnlockCeilingNits = 2000;

constexpr DWORD kProcessAccess = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ |
                                  PROCESS_VM_WRITE | PROCESS_VM_OPERATION;
constexpr std::size_t kKernelSize = rtxhdr::kKernelSize;
constexpr std::uintptr_t kSizeFieldDelta = 0x0c;
constexpr char kNvAiHash[] =
    "b486759f579b9a08207afd2ef1311e381c021df9098e84e66be4315c1d513766";
constexpr char kNvWgfHash[] =
    "bb6c170021de9a722eb16c6368faafda0266831d6ba9e8e343bce131f35949dc";
constexpr char kKernelHash[] =
    "f08e2619636e181ecf0fddbee78488b6719f47521ccb8595b5fb12fff6a8d6c6";

constexpr std::uintptr_t kNvAiRva = 0x2bfb60;
constexpr std::uintptr_t kNvWgfRva = 0x47b8910;
constexpr std::uintptr_t kCodeOffset = 0x980;

constexpr std::array<std::uint32_t, 18> kToleranceInstructions = {
    0x31a0, 0x31f0, 0x3210, 0x3510, 0x3560, 0x3580,
    0xbe40, 0xbe90, 0xbeb0, 0xc1b0, 0xc200, 0xc220,
    0x16450, 0x164a0, 0x164c0, 0x167c0, 0x16810, 0x16830};
constexpr std::array<std::uint32_t, 18> kPeakInstructions = {
    0x3630, 0x3640, 0x3670, 0x3680, 0x3690, 0x36e0,
    0xc2a0, 0xc2b0, 0xc2e0, 0xc2f0, 0xc300, 0xc350,
    0x168b0, 0x168c0, 0x168f0, 0x16900, 0x16910, 0x16960};

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

std::optional<std::array<std::uint8_t, 32>> Sha256File(const std::wstring& path) {
  Handle file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE |
                                        FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                                        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                                        nullptr));
  if (!file) return std::nullopt;

  BCRYPT_ALG_HANDLE algorithm = nullptr;
  BCRYPT_HASH_HANDLE hash = nullptr;
  DWORD objectLength = 0;
  DWORD resultLength = 0;
  if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0 ||
      BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                        reinterpret_cast<PUCHAR>(&objectLength), sizeof(objectLength),
                        &resultLength, 0) < 0) {
    if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
    return std::nullopt;
  }
  std::vector<UCHAR> object(objectLength);
  if (BCryptCreateHash(algorithm, &hash, object.data(), objectLength, nullptr, 0, 0) < 0) {
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return std::nullopt;
  }
  std::array<std::uint8_t, 64 * 1024> buffer{};
  DWORD read = 0;
  bool ok = true;
  for (;;) {
    if (!ReadFile(file.get(), buffer.data(), static_cast<DWORD>(buffer.size()), &read,
                  nullptr)) {
      ok = false;
      break;
    }
    if (read == 0) break;
    if (BCryptHashData(hash, buffer.data(), read, 0) < 0) {
      ok = false;
      break;
    }
  }
  std::array<std::uint8_t, 32> digest{};
  if (ok && BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) < 0)
    ok = false;
  BCryptDestroyHash(hash);
  BCryptCloseAlgorithmProvider(algorithm, 0);
  if (!ok) return std::nullopt;
  return digest;
}

std::optional<std::array<std::uint8_t, 32>> Sha256Bytes(const std::uint8_t* data,
                                                        std::size_t size) {
  BCRYPT_ALG_HANDLE algorithm = nullptr;
  BCRYPT_HASH_HANDLE hash = nullptr;
  DWORD objectLength = 0;
  DWORD resultLength = 0;
  if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0 ||
      BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                        reinterpret_cast<PUCHAR>(&objectLength), sizeof(objectLength),
                        &resultLength, 0) < 0) {
    if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
    return std::nullopt;
  }
  std::vector<UCHAR> object(objectLength);
  if (BCryptCreateHash(algorithm, &hash, object.data(), objectLength, nullptr, 0, 0) < 0) {
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return std::nullopt;
  }
  bool ok = BCryptHashData(hash, const_cast<PUCHAR>(data), static_cast<ULONG>(size), 0) >= 0;
  std::array<std::uint8_t, 32> digest{};
  if (ok && BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) < 0)
    ok = false;
  BCryptDestroyHash(hash);
  BCryptCloseAlgorithmProvider(algorithm, 0);
  if (!ok) return std::nullopt;
  return digest;
}

struct ModuleSpec {
  const wchar_t* name;
  const char* fileSha256;
  std::uintptr_t rva;
  bool hasSizeField;
  std::uintptr_t ptxRva;
};

constexpr std::array<ModuleSpec, 2> kModules = {{
    {L"nvAIHDRx.dll", kNvAiHash, kNvAiRva, true, 0x359170},
    {L"nvwgf2umx.dll", kNvWgfHash, kNvWgfRva, false, 0x45d6450},
}};

const ModuleSpec* FindSpec(const std::wstring& name) {
  const std::wstring lower = Lower(name);
  for (const auto& spec : kModules) {
    if (lower == Lower(spec.name)) return &spec;
  }
  return nullptr;
}

struct ModuleInfo {
  ModuleSpec spec{};
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
    const ModuleSpec* spec = FindSpec(entry.szModule);
    if (spec) {
      ModuleInfo info;
      info.spec = *spec;
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

bool IsRangeReadable(HANDLE process, std::uintptr_t address, std::size_t size) {
  MEMORY_BASIC_INFORMATION info{};
  if (!VirtualQueryEx(process, reinterpret_cast<const void*>(address), &info,
                      sizeof(info)))
    return false;
  const auto begin = reinterpret_cast<std::uintptr_t>(info.BaseAddress);
  if (info.State != MEM_COMMIT || address < begin) return false;
  const auto available = info.RegionSize - (address - begin);
  return available >= size;
}

enum class RangeState { kOriginal, kPatched, kUnknown };

enum class CodeSource { kCubin = 0, kPtx = 1 };
constexpr std::array<CodeSource, 2> kCodeSources = {CodeSource::kCubin, CodeSource::kPtx};
using CodeVariants = std::array<std::vector<std::uint8_t>, 2>;

const char* SourceName(CodeSource source) {
  return source == CodeSource::kCubin ? "CUBIN" : "PTX";
}

std::size_t SourceSize(CodeSource source) {
  return source == CodeSource::kCubin ? kKernelSize : rtxhdr::kPtxSize;
}

std::uintptr_t SourceRva(const ModuleSpec& module, CodeSource source) {
  return source == CodeSource::kCubin ? module.rva : module.ptxRva;
}

std::uint32_t ReadU32(const std::vector<std::uint8_t>& bytes, std::size_t offset) {
  std::uint32_t value = 0;
  std::memcpy(&value, bytes.data() + offset, sizeof(value));
  return value;
}

void WriteU32(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint32_t value) {
  std::memcpy(bytes.data() + offset, &value, sizeof(value));
}

std::uint32_t FloatBits(float value) {
  std::uint32_t bits = 0;
  std::memcpy(&bits, &value, sizeof(bits));
  return bits;
}

float BitsFloat(std::uint32_t bits) {
  float value = 0;
  std::memcpy(&value, &bits, sizeof(value));
  return value;
}

std::vector<std::size_t> ChangedOffsets() {
  std::vector<std::size_t> offsets;
  offsets.reserve(36);
  for (const auto instruction : kToleranceInstructions)
    offsets.push_back(kCodeOffset + instruction + 4);
  for (const auto instruction : kPeakInstructions)
    offsets.push_back(kCodeOffset + instruction + 4);
  return offsets;
}

bool IsOriginal(const std::vector<std::uint8_t>& bytes) {
  if (bytes.size() != kKernelSize) return false;
  return std::memcmp(bytes.data(), rtxhdr::kOriginalKernel.data(), kKernelSize) == 0;
}

bool IsPatched(const std::vector<std::uint8_t>& bytes, int* peakNits = nullptr) {
  if (bytes.size() != kKernelSize) return false;
  const auto offsets = ChangedOffsets();
  std::vector<bool> changed(kKernelSize, false);
  for (const auto offset : offsets)
    for (std::size_t i = 0; i < 4; ++i) changed[offset + i] = true;
  for (std::size_t i = 0; i < kKernelSize; ++i) {
    if (!changed[i] && bytes[i] != rtxhdr::kOriginalKernel[i]) return false;
  }
  const std::uint32_t tolerance = ReadU32(bytes, offsets[0]);
  const std::uint32_t peak = ReadU32(bytes, offsets[18]);
  if (tolerance == 0x3f8020c5) return false;
  for (std::size_t i = 0; i < 18; ++i) {
    if (ReadU32(bytes, offsets[i]) != tolerance ||
        ReadU32(bytes, offsets[18 + i]) != peak)
      return false;
  }
  for (int setting = 1000; setting <= 2000; ++setting) {
    // Match the Python generator: perform the division in double precision
    // and round once when converting to the SASS float immediate.
    const auto expectedPeak =
        FloatBits(static_cast<float>(static_cast<double>(setting) / 1000.0));
    const auto expectedTolerance =
        FloatBits(static_cast<float>(static_cast<double>(setting + 1) / 1000.0));
    if (peak == expectedPeak && tolerance == expectedTolerance) {
      if (peakNits) *peakNits = setting;
      return true;
    }
  }
  return false;
}

std::optional<std::vector<std::uint8_t>> BuildVariant(int peakNits) {
  if (peakNits < 1000 || peakNits > 2000) return std::nullopt;
  std::vector<std::uint8_t> bytes(rtxhdr::kOriginalKernel.begin(),
                                  rtxhdr::kOriginalKernel.end());
  const std::uint32_t tolerance =
      FloatBits(static_cast<float>(static_cast<double>(peakNits + 1) / 1000.0));
  const std::uint32_t peak =
      FloatBits(static_cast<float>(static_cast<double>(peakNits) / 1000.0));
  for (const auto instruction : kToleranceInstructions) {
    const std::size_t offset = kCodeOffset + instruction + 4;
    if (ReadU32(bytes, offset) != 0x3f8020c5) return std::nullopt;
    WriteU32(bytes, offset, tolerance);
  }
  for (const auto instruction : kPeakInstructions) {
    const std::size_t offset = kCodeOffset + instruction + 4;
    if (ReadU32(bytes, offset) != 0x3f800000) return std::nullopt;
    WriteU32(bytes, offset, peak);
  }
  return bytes;
}

bool IsOriginalPtx(const std::vector<std::uint8_t>& bytes) {
  return bytes.size() == rtxhdr::kPtxSize &&
         std::memcmp(bytes.data(), rtxhdr::kOriginalPtx.data(), bytes.size()) == 0;
}

std::optional<std::uint32_t> ReadPtxLiteral(const std::vector<std::uint8_t>& bytes,
                                         std::size_t offset) {
  if (offset > bytes.size() || bytes.size() - offset < 10 ||
      bytes[offset] != '0' || bytes[offset + 1] != 'f') return std::nullopt;
  std::uint32_t bits = 0;
  for (std::size_t i = 2; i < 10; ++i) {
    const auto c = bytes[offset + i];
    if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F'))) return std::nullopt;
    bits = (bits << 4) | static_cast<std::uint32_t>(c <= '9' ? c - '0' : c - 'A' + 10);
  }
  return bits;
}

void WritePtxLiteral(std::vector<std::uint8_t>& bytes, std::size_t offset,
                     std::uint32_t bits) {
  char literal[11]{};
  std::snprintf(literal, sizeof(literal), "0f%08X", static_cast<unsigned int>(bits));
  std::memcpy(bytes.data() + offset, literal, 10);
}

bool IsPatchedPtx(const std::vector<std::uint8_t>& bytes, int* peakNits = nullptr) {
  if (bytes.size() != rtxhdr::kPtxSize) return false;
  std::vector<std::uint8_t> normalized(bytes);
  std::optional<std::uint32_t> peak;
  std::optional<std::uint32_t> tolerance;
  for (const auto& site : rtxhdr::kPtxLiteralSites) {
    const auto bits = ReadPtxLiteral(bytes, site.offset);
    if (!bits) return false;
    auto& expected = site.tolerance ? tolerance : peak;
    if (expected && *expected != *bits) return false;
    expected = bits;
    std::memcpy(normalized.data() + site.offset, rtxhdr::kOriginalPtx.data() + site.offset, 10);
  }
  if (!peak || !tolerance || !IsOriginalPtx(normalized)) return false;
  for (int setting = 1001; setting <= 2000; ++setting) {
    if (*peak == FloatBits(static_cast<float>(static_cast<double>(setting) / 1000.0)) &&
        *tolerance == FloatBits(static_cast<float>(static_cast<double>(setting + 1) / 1000.0))) {
      if (peakNits) *peakNits = setting;
      return true;
    }
  }
  return false;
}

std::optional<std::vector<std::uint8_t>> BuildPtxVariant(int peakNits) {
  if (peakNits < 1000 || peakNits > 2000) return std::nullopt;
  std::vector<std::uint8_t> bytes(rtxhdr::kOriginalPtx.begin(), rtxhdr::kOriginalPtx.end());
  const auto tolerance = FloatBits(static_cast<float>(static_cast<double>(peakNits + 1) / 1000.0));
  const auto peak = FloatBits(static_cast<float>(static_cast<double>(peakNits) / 1000.0));
  for (const auto& site : rtxhdr::kPtxLiteralSites) {
    const auto original = ReadPtxLiteral(bytes, site.offset);
    if (!original || *original != (site.tolerance ? 0x3f8020c5u : 0x3f800000u))
      return std::nullopt;
    WritePtxLiteral(bytes, site.offset, site.tolerance ? tolerance : peak);
  }
  return bytes;
}

std::optional<CodeVariants> BuildCodeVariants(int peakNits) {
  auto cubin = BuildVariant(peakNits);
  auto ptx = BuildPtxVariant(peakNits);
  if (!cubin || !ptx) return std::nullopt;
  return CodeVariants{{std::move(*cubin), std::move(*ptx)}};
}

bool SelfTest() {
  const std::vector<std::uint8_t> original(rtxhdr::kOriginalKernel.begin(),
                                           rtxhdr::kOriginalKernel.end());
  if (original.size() != kKernelSize || !IsOriginal(original)) {
    RTXHDR_ERR << "Self-test failed: embedded original CUBIN length/content mismatch\n";
    return false;
  }
  const auto digest = Sha256Bytes(original.data(), original.size());
  if (!digest || _stricmp(Hex(*digest).c_str(), kKernelHash) != 0) {
    RTXHDR_ERR << "Self-test failed: original CUBIN SHA256 mismatch\n";
    if (digest) RTXHDR_ERR << "  actual=" << Hex(*digest) << "\n";
    return false;
  }
  RTXHDR_OUT << "Original CUBIN: " << original.size() << " bytes, SHA256=" << Hex(*digest)
            << "\n";
  for (const int setting : {1000, 1260, 2000}) {
    const auto variant = BuildVariant(setting);
    if (!variant) {
      RTXHDR_ERR << "Self-test failed: could not generate peak " << setting << "\n";
      return false;
    }
    int detected = 0;
    const bool recognized = setting == 1000 ? IsOriginal(*variant)
                                           : IsPatched(*variant, &detected);
    if (!recognized || (setting != 1000 && detected != setting)) {
      RTXHDR_ERR << "Self-test failed: peak " << setting << " variant validation failed\n";
      return false;
    }
    const auto variantHash = Sha256Bytes(variant->data(), variant->size());
    std::size_t changed = 0;
    for (std::size_t i = 0; i < original.size(); ++i)
      changed += original[i] != (*variant)[i] ? 1u : 0u;
    RTXHDR_OUT << "Variant peak " << setting << ": changed=" << changed
              << ", SHA256=" << (variantHash ? Hex(*variantHash) : "<hash failed>") << "\n";
    const std::size_t expectedChanged = setting == 1000 ? 0u : 108u;
    if (changed != expectedChanged || !variantHash) {
      RTXHDR_ERR << "Self-test failed: peak " << setting << " immediate-change count mismatch\n";
      return false;
    }
  }
  const std::vector<std::uint8_t> originalPtx(rtxhdr::kOriginalPtx.begin(),
                                              rtxhdr::kOriginalPtx.end());
  const auto ptxHash = Sha256Bytes(originalPtx.data(), originalPtx.size());
  if (!ptxHash || Hex(*ptxHash) != rtxhdr::kPtxSha256 || !IsOriginalPtx(originalPtx)) {
    RTXHDR_ERR << "Self-test failed: original PTX length/content/SHA256 mismatch\n";
    return false;
  }
  RTXHDR_OUT << "Original PTX: " << originalPtx.size() << " bytes, SHA256=" << Hex(*ptxHash) << "\n";
  for (const int setting : {1000, 1001, 1260, 2000}) {
    const auto variant = BuildPtxVariant(setting);
    int detected = 0;
    if (!variant || !(setting == 1000 ? IsOriginalPtx(*variant)
                                     : IsPatchedPtx(*variant, &detected)) ||
        (setting != 1000 && detected != setting)) {
      RTXHDR_ERR << "Self-test failed: PTX peak " << setting << " variant validation failed\n";
      return false;
    }
    const auto variantHash = Sha256Bytes(variant->data(), variant->size());
    if (!variantHash || (setting == 1260 && Hex(*variantHash) !=
        "0e431ae0c97477eb37dbd38618d184f4715529ab878007c72aae3a2f14a69c39")) {
      RTXHDR_ERR << "Self-test failed: PTX variant does not match the independently generated manifest\n";
      return false;
    }
    std::size_t changed = 0;
    for (std::size_t i = 0; i < originalPtx.size(); ++i)
      changed += originalPtx[i] != (*variant)[i] ? 1u : 0u;
    RTXHDR_OUT << "PTX variant peak " << setting << ": changed=" << changed
              << ", SHA256=" << Hex(*variantHash) << "\n";
  }
  auto damagedPtx = *BuildPtxVariant(1260);
  damagedPtx.front() ^= 1;
  if (IsOriginalPtx(damagedPtx) || IsPatchedPtx(damagedPtx) ||
      BuildPtxVariant(999) || BuildPtxVariant(2001)) {
    RTXHDR_ERR << "Self-test failed: invalid PTX range or unknown bytes were not rejected\n";
    return false;
  }
  RTXHDR_OUT << "Self-test passed (no other process was accessed)\n";
  return true;
}

std::string StateText(RangeState state, int peak = 0) {
  switch (state) {
    case RangeState::kOriginal:
      return "original";
    case RangeState::kPatched:
      return peak ? "patched(" + std::to_string(peak) + " nits)" : "patched";
    default:
      return "unknown/rejected";
  }
}

bool QueryRange(HANDLE process, const ModuleInfo& module, std::vector<std::uint8_t>& bytes,
                RangeState& state, int* peak = nullptr, CodeSource source = CodeSource::kCubin) {
  state = RangeState::kUnknown;
  if (peak) *peak = 0;
  const auto rva = SourceRva(module.spec, source);
  const auto size = SourceSize(source);
  if (rva > module.size || size > static_cast<std::size_t>(module.size - rva)) {
    RTXHDR_ERR << Narrow(module.name) << ": " << SourceName(source)
              << " range is outside the module image; access denied\n";
    return false;
  }
  if (!IsRangeReadable(process, module.base + rva, size)) return false;
  bytes.resize(size);
  if (!ReadRemote(process, module.base + rva, bytes.data(), bytes.size()))
    return false;
  if (source == CodeSource::kCubin ? IsOriginal(bytes) : IsOriginalPtx(bytes)) {
    state = RangeState::kOriginal;
  } else if (source == CodeSource::kCubin ? IsPatched(bytes, peak) : IsPatchedPtx(bytes, peak)) {
    state = RangeState::kPatched;
  } else {
    state = RangeState::kUnknown;
  }
  return true;
}

bool ValidateModuleFile(const ModuleInfo& module, std::string* actual = nullptr) {
  const auto digest = Sha256File(module.path);
  if (!digest) {
    RTXHDR_ERR << "Failed to read module hash: " << Narrow(module.path) << "\n";
    return false;
  }
  const std::string value = Hex(*digest);
  if (actual) *actual = value;
  if (_stricmp(value.c_str(), module.spec.fileSha256) != 0) {
    RTXHDR_ERR << "Version mismatch; write refused: " << Narrow(module.path) << "\n"
              << "  actual SHA256=" << value << "\n"
              << "  expected SHA256=" << module.spec.fileSha256 << "\n";
    return false;
  }
  return true;
}

bool ValidateSizeField(HANDLE process, const ModuleInfo& module) {
  if (!module.spec.hasSizeField) return true;
  std::uint32_t size = 0;
  if (!ReadRemote(process, module.base + module.spec.rva - kSizeFieldDelta, &size,
                  sizeof(size))) {
    RTXHDR_ERR << "Failed to read the CUBIN size field\n";
    return false;
  }
  if (size != kKernelSize) {
    RTXHDR_ERR << "CUBIN size mismatch: " << size << ", expected " << kKernelSize << "\n";
    return false;
  }
  return true;
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

bool UpdateModuleSources(HANDLE process, DWORD pid, const ModuleInfo& module,
                         const CodeVariants& targets, int peakNits, bool restore,
                         bool quietIfAlready, bool debugEventStopped = false,
                         bool moduleAlreadyLoaded = false) {
  if (!ValidateModuleFile(module) || !ValidateSizeField(process, module)) return false;
  CodeVariants current;
  std::array<RangeState, 2> states{};
  std::array<int, 2> peaks{};
  // Validate both carriers before writing either. In particular, an older
  // CUBIN-only patch is not complete when the PTX carrier is still original.
  for (const auto source : kCodeSources) {
    const auto i = static_cast<std::size_t>(source);
    if (!QueryRange(process, module, current[i], states[i], &peaks[i], source)) {
      RTXHDR_ERR << Narrow(module.name) << ": failed to read the " << SourceName(source) << " range\n";
      return false;
    }
  }
  const bool already = current == targets;
  if (!(quietIfAlready && already)) {
    for (const auto source : kCodeSources) {
      const auto i = static_cast<std::size_t>(source);
      RTXHDR_OUT << "PID " << pid << ' ' << Narrow(module.name) << ' ' << SourceName(source)
                << " CPU source data " << StateText(states[i], peaks[i]) << "\n";
    }
  }
  for (const auto source : kCodeSources) {
    const auto i = static_cast<std::size_t>(source);
    if (states[i] == RangeState::kUnknown) {
      RTXHDR_ERR << "Write refused: " << SourceName(source) << " bytes are not a known original or variant\n";
      return false;
    }
  }
  if (already) {
    if (!quietIfAlready)
      RTXHDR_OUT << "CUBIN and PTX CPU source data already match the target; this does not prove the GPU reloaded them\n";
    return true;
  }

  CodeVariants check = current;
  SuspendedThreads suspended(pid);
  if (!debugEventStopped && !suspended.SuspendAll()) return false;
  for (const auto source : kCodeSources) {
    const auto i = static_cast<std::size_t>(source);
    const auto address = module.base + SourceRva(module.spec, source);
    if (!ReadRemote(process, address, check[i].data(), check[i].size()) || check[i] != current[i]) {
      RTXHDR_ERR << SourceName(source) << " changed after threads were suspended; refusing to overwrite either code source\n";
      return false;
    }
  }
  std::array<bool, 2> written{};
  for (const auto source : kCodeSources) {
    const auto i = static_cast<std::size_t>(source);
    if (current[i] == targets[i]) continue;
    const auto address = module.base + SourceRva(module.spec, source);
    // Both writes share one thread-suspension window. WriteRemote still checks
    // its own snapshot and verifies write/readback/protection restoration.
    if (!WriteRemote(process, pid, address, current[i], targets[i], true)) {
      RTXHDR_ERR << SourceName(source) << " update failed; rolling back other code sources changed in this transaction\n";
      for (std::size_t previous = i; previous-- > 0;) {
        if (!written[previous]) continue;
        const auto priorSource = static_cast<CodeSource>(previous);
        if (!WriteRemote(process, pid, module.base + SourceRva(module.spec, priorSource),
                         targets[previous], current[previous], true)) {
          RTXHDR_ERR << SourceName(priorSource) << " cross-source rollback failed; complete restoration cannot be confirmed\n";
        }
      }
      return false;
    }
    written[i] = true;
  }
  for (const auto source : kCodeSources) {
    if (written[static_cast<std::size_t>(source)])
      RTXHDR_OUT << (restore ? "Restored" : "Wrote") << " and verified by readback "
                << Narrow(module.name) << ' ' << SourceName(source) << "\n";
  }
  RTXHDR_OUT << "CUBIN and PTX CPU source data were " << (restore ? "restored to the original state" : "matched to peak " +
      std::to_string(peakNits) + " nits");
  if (moduleAlreadyLoaded) RTXHDR_OUT << "; the module already existed when attached and running GPU kernels will not refresh automatically";
  else if (debugEventStopped) RTXHDR_OUT << "; the module-load event has not yet been released";
  else RTXHDR_OUT << "; running GPU kernels will not refresh automatically";
  RTXHDR_OUT << "\n";
  return true;
}

}  // namespace
