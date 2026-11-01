"""Generate x64 ABI-preserving proxy thunks from the local System32 export table."""
import argparse
import json
import os
from pathlib import Path

import pefile


KINDS = ('dxgi', 'winmm', 'version', 'winhttp', 'psapi')


def generate_universal(output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    libraries = {}
    named = {}
    ordinals = set()
    for kind in KINDS:
        source = Path(os.environ['SystemRoot']) / 'System32' / f'{kind}.dll'
        pe = pefile.PE(str(source), fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
        entries = []
        for entry in sorted(pe.DIRECTORY_ENTRY_EXPORT.symbols, key=lambda e: e.ordinal):
            name = entry.name.decode('ascii') if entry.name else None
            entries.append({'name': name, 'ordinal': entry.ordinal})
            ordinals.add(entry.ordinal)
            if name:
                named.setdefault(name, []).append(kind)
        libraries[kind] = entries
        pe.close()
    if max(ordinals) >= 1000:
        raise ValueError('System ordinals conflict with reserved proxy diagnostic range')
    declarations = [
        'inline constexpr bool kUniversalProxy = true;',
        'inline constexpr wchar_t kProxyLibrary[] = L"";',
        'inline constexpr const wchar_t* kProxyLibraries[] = {' +
        ', '.join(f'L"{k}.dll"' for k in KINDS) + '};',
        'struct ProxyExport { const char* name; unsigned short ordinal; };',
        f'inline constexpr unsigned kProxyExportCount = {len(named) + len(ordinals)};',
        'inline constexpr ProxyExport kProxyExports[] = {']
    definition = ['LIBRARY RtxHdrUnlock', 'EXPORTS',
                  '  InitializeASI @1001', '  RtxHdrUnlockInitialize @1002',
                  '  RtxHdrUnlockGetStatus @1003']
    assembly = ['option casemap:none', 'EXTERN ProxyResolve:PROC', '.code']
    # Named exports have disjoint, high ordinals. The original low ordinals
    # each get a dedicated runtime dispatcher; one PE slot cannot represent
    # five conflicting name-to-ordinal mappings at the same time.
    dispatch = [(None, ordinal, ordinal) for ordinal in sorted(ordinals)]
    dispatch += [(name, 0, 2000 + i) for i, name in enumerate(sorted(named))]
    for index, (name, source_ordinal, export_ordinal) in enumerate(dispatch):
        declarations.append(f'  {{{json.dumps(name) if name else "nullptr"}, {source_ordinal}}},')
        stub = f'ProxyThunk{index}'
        definition.append(f'  {name or stub}={stub} @{export_ordinal}' + ('' if name else ' NONAME'))
        assembly.extend(make_thunk(stub, index))
    declarations.append('};')
    assembly.append('END')
    (output / 'proxy_exports.h').write_text('\n'.join(declarations) + '\n', encoding='utf-8')
    (output / 'proxy.def').write_text('\n'.join(definition) + '\n', encoding='ascii')
    (output / 'proxy.asm').write_text('\n'.join(assembly) + '\n', encoding='ascii')
    manifest = {'libraries': libraries, 'named_export_count': len(named),
                'ordinal_dispatch_count': len(ordinals), 'named_ordinal_base': 2000,
                'export_count': len(dispatch) + 3}
    (output / 'exports.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    print(f'universal: {len(named)} named exports + {len(ordinals)} runtime ordinal dispatchers')


def make_thunk(stub: str, index: int) -> list[str]:
    # Preserve the original caller register and stack arguments, including XMM.
    return [f'{stub} PROC FRAME', '  sub rsp, 88h', '  .allocstack 88h',
            '  .endprolog', '  mov [rsp+20h], rcx', '  mov [rsp+28h], rdx',
            '  mov [rsp+30h], r8', '  mov [rsp+38h], r9',
            '  movdqu [rsp+40h], xmm0', '  movdqu [rsp+50h], xmm1',
            '  movdqu [rsp+60h], xmm2', '  movdqu [rsp+70h], xmm3',
            f'  mov ecx, {index}', '  call ProxyResolve',
            '  mov rcx, [rsp+20h]', '  mov rdx, [rsp+28h]',
            '  mov r8, [rsp+30h]', '  mov r9, [rsp+38h]',
            '  movdqu xmm0, [rsp+40h]', '  movdqu xmm1, [rsp+50h]',
            '  movdqu xmm2, [rsp+60h]', '  movdqu xmm3, [rsp+70h]',
            '  add rsp, 88h', '  jmp rax', f'{stub} ENDP']


def generate(kind: str, output: Path) -> None:
    if kind == 'universal':
        generate_universal(output)
        return
    output.mkdir(parents=True, exist_ok=True)
    entries = []
    if kind != 'asi':
        source = Path(os.environ['SystemRoot']) / 'System32' / f'{kind}.dll'
        pe = pefile.PE(str(source), fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
        entries = sorted(pe.DIRECTORY_ENTRY_EXPORT.symbols, key=lambda x: x.ordinal)
    declarations = ['inline constexpr bool kUniversalProxy = false;',
                    'inline constexpr const wchar_t* kProxyLibraries[] = {L""};',
                    f'inline constexpr wchar_t kProxyLibrary[] = L"{kind}.dll";',
                    'struct ProxyExport { const char* name; unsigned short ordinal; };',
                    f'inline constexpr unsigned kProxyExportCount = {len(entries)};',
                    'inline constexpr ProxyExport kProxyExports[] = {']
    definition = ['LIBRARY ' + ('RtxHdrUnlock' if kind == 'asi' else kind), 'EXPORTS',
                  '  InitializeASI @1001', '  RtxHdrUnlockInitialize @1002',
                  '  RtxHdrUnlockGetStatus @1003']
    assembly = ['option casemap:none', 'EXTERN ProxyResolve:PROC',
                'EXTERN ProxyTargets:QWORD', '.code']
    manifest = []
    for index, entry in enumerate(entries):
        name = entry.name.decode('ascii') if entry.name else None
        declarations.append(f'  {{{json.dumps(name) if name else "nullptr"}, {entry.ordinal}}},')
        stub = f'ProxyThunk{index}'
        definition.append(f'  {name or stub}={stub} @{entry.ordinal}' + ('' if name else ' NONAME'))
        # Entry RSP is 8 mod 16. Reserve shadow space + argument save slots;
        # original caller stack arguments remain untouched for the tail jump.
        assembly.extend(make_thunk(stub, index))
        manifest.append({'name': name, 'ordinal': entry.ordinal})
    if not entries:
        declarations.append('  {nullptr, 0},')
    declarations.append('};')
    assembly.append('END')
    (output / 'proxy_exports.h').write_text('\n'.join(declarations)+'\n', encoding='utf-8')
    (output / 'proxy.def').write_text('\n'.join(definition)+'\n', encoding='ascii')
    (output / 'proxy.asm').write_text('\n'.join(assembly)+'\n', encoding='ascii')
    (output / 'exports.json').write_text(json.dumps(manifest, indent=2)+'\n', encoding='utf-8')
    print(f'{kind}: {len(entries)} system exports (names and ordinals preserved)')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('kind', choices=[*KINDS, 'asi', 'universal'])
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    generate(args.kind, args.output)
