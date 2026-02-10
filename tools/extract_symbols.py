#!/usr/bin/env python3
"""
FFCC-Decomp Symbol Extraction Script
Extracts relevant symbol info from MAP files without loading massive files into context.
"""

import re
import sys
from pathlib import Path

EN_FOUND_IN_RE = re.compile(r"^\s*\d+\]\s*(.+?)\s*\(([^)]+)\)\s+found in\s+(.+)$")

# NOTE: MAP-derived addresses/sizes may not match your current build.
WARNING_BUILD_MISMATCH = (
    "⚠️WARNING: ADDRESS AND SIZES ARE FOR A DIFFERENT BUILD AND COULD BE WRONG. ALWAYS CHECK GHIDRA. ⚠️"
)

def warn_build_mismatch():
    """Print a warning immediately before reporting any address/size."""
    print(WARNING_BUILD_MISMATCH)

def extract_symbols_for_function(map_file, function_name):
    """Extract symbol information for a specific function"""
    results = []

    try:
        with open(map_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()

                # Look for function symbols (contains the function name)
                if function_name in line:
                    # Try to parse common MAP file formats
                    # Format: address size section name
                    parts = line.split()
                    if len(parts) >= 4:
                        results.append({
                            'line': line_num,
                            'content': line,
                            'parsed': {
                                'address': parts[0] if parts[0].startswith('0x') else None,
                                'size': parts[1] if len(parts) > 1 else None,
                                'section': parts[2] if len(parts) > 2 else None,
                                'symbol': ' '.join(parts[3:]) if len(parts) > 3 else None
                            }
                        })
                    else:
                        results.append({
                            'line': line_num,
                            'content': line,
                            'parsed': None
                        })

                # Stop after finding reasonable number of matches
                if len(results) >= 20:
                    break

    except Exception as e:
        return [{'error': f"Failed to read {map_file}: {e}"}]

    return results

def extract_symbols_for_unit(map_file, unit_name):
    """Extract symbols for a source unit (e.g., all functions from a .cpp file)"""
    # Convert unit name to potential source file patterns
    source_patterns = []
    if '/' in unit_name:
        base_name = unit_name.split('/')[-1]
        source_patterns.extend([
            f"{base_name}.c",
            f"{base_name}.cpp",
            f"{base_name}.s",
        ])

    results = []

    try:
        with open(map_file, 'r', encoding='utf-8', errors='ignore') as f:
            current_section = None
            for line_num, line in enumerate(f, 1):
                line_stripped = line.strip()

                # Track sections
                if line_stripped.startswith('.'):
                    current_section = line_stripped

                # Look for symbols related to our patterns
                for pattern in source_patterns:
                    if pattern in line:
                        results.append({
                            'line': line_num,
                            'section': current_section,
                            'content': line_stripped,
                            'pattern_match': pattern
                        })

                # Stop after reasonable number of matches
                if len(results) >= 50:
                    break

    except Exception as e:
        return [{'error': f"Failed to read {map_file}: {e}"}]

    return results

def extract_section_info(map_file, section_name):
    """Extract section information and global variables"""
    results = []
    in_section = False

    try:
        with open(map_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                line_stripped = line.strip()

                # Check if we're entering the target section
                if section_name in line_stripped and 'section layout' in line_stripped:
                    in_section = True
                    results.append({
                        'line': line_num,
                        'type': 'section_header',
                        'content': line_stripped
                    })
                    continue

                # If we're in the section, collect data until we hit another section
                if in_section:
                    # Stop at next section
                    if line_stripped.startswith('.') and 'section layout' in line_stripped and section_name not in line_stripped:
                        break

                    # Skip empty lines
                    if not line_stripped:
                        continue

                    # Parse data entries (address size virtual_addr flags section_type object_file)
                    parts = line_stripped.split()
                    if len(parts) >= 6 and parts[0] != section_name:
                        results.append({
                            'line': line_num,
                            'type': 'data_entry',
                            'content': line_stripped,
                            'parsed': {
                                'offset': parts[0],
                                'size': parts[1],
                                'virtual_addr': parts[2],
                                'flags': parts[3],
                                'section': parts[4],
                                'object_file': parts[5]
                            }
                        })

                # Stop after reasonable number
                if len(results) >= 30:
                    break

    except Exception as e:
        return [{'error': f"Failed to read {map_file}: {e}"}]

    return results

def extract_globals_for_file(map_file, object_file):
    """Extract global variables for a specific object file"""
    results = []

    try:
        with open(map_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                line_stripped = line.strip()

                # Look for lines that reference our object file
                if object_file in line_stripped:
                    # Check if it's a data/bss entry (not .text)
                    parts = line_stripped.split()
                    if len(parts) >= 5 and (parts[4] == '.data' or parts[4] == '.bss' or parts[4] == '.sdata'):
                        results.append({
                            'line': line_num,
                            'content': line_stripped,
                            'section': parts[4],
                            'parsed': {
                                'offset': parts[0],
                                'size': parts[1],
                                'virtual_addr': parts[2],
                                'flags': parts[3],
                                'section': parts[4],
                                'symbol': ' '.join(parts[5:]) if len(parts) > 5 else 'unnamed'
                            }
                        })

                if len(results) >= 20:
                    break

    except Exception as e:
        return [{'error': f"Failed to read {map_file}: {e}"}]

    return results

def _parse_en_found_in(line_stripped):
    match = EN_FOUND_IN_RE.match(line_stripped)
    if not match:
        return None
    symbol_name = match.group(1).strip()
    type_info = match.group(2).strip()
    object_file = match.group(3).strip()
    return {
        'flag': 'EN',
        'offset': 'unknown',
        'size': 'unknown',
        'virtual_addr': 'unknown',
        'type_flag': type_info,
        'symbol': symbol_name,
        'object_file': object_file
    }

def _parse_pal_line(line_stripped):
    # PAL format: "flag offset size addr type symbol [object info]"
    if line_stripped.startswith('UNUSED'):
        parts = line_stripped.split()
        if len(parts) >= 5:
            size = parts[1]
            symbol = parts[3] if len(parts) > 3 else 'unnamed'
            object_info = ' '.join(parts[4:]) if len(parts) > 4 else ''
            return {
                'flag': 'UNUSED',
                'offset': 'UNUSED',
                'size': size,
                'virtual_addr': 'UNUSED',
                'type_flag': 'UNUSED',
                'symbol': symbol,
                'object_file': object_info
            }
        return None

    if 'UNUSED' in line_stripped and len(line_stripped.split()) >= 6:
        parts = line_stripped.split()
        flag = parts[0]
        size = parts[2]
        symbol = parts[4] if len(parts) > 4 else 'unnamed'
        object_info = ' '.join(parts[5:]) if len(parts) > 5 else ''
        return {
            'flag': flag,
            'offset': 'UNUSED',
            'size': size,
            'virtual_addr': 'UNUSED',
            'type_flag': 'UNUSED',
            'symbol': symbol,
            'object_file': object_info
        }

    parts = line_stripped.split()
    if len(parts) >= 6:
        flag = parts[0]
        offset = parts[1]
        size = parts[2]
        virtual_addr = parts[3]
        type_flag = parts[4]
        symbol = parts[5]
        object_info = ' '.join(parts[6:]) if len(parts) > 6 else ''
        return {
            'flag': flag,
            'offset': offset,
            'size': size,
            'virtual_addr': virtual_addr,
            'type_flag': type_flag,
            'symbol': symbol,
            'object_file': object_info
        }

    return None

def _categorize_entry(entry, functions, globals_data, sections):
    if not entry:
        return
    flag = entry.get('flag', '')
    type_flag = entry.get('type_flag', '')
    symbol = entry.get('symbol', '')

    if (flag == 'G' and (type_flag == '4' or type_flag == 'UNUSED')) or 'func' in type_flag:
        functions.append({'parsed': entry})
    elif flag == 'UNUSED' or \
         (type_flag == '4' and flag != 'G') or \
         type_flag in ['.data', '.bss', '.sdata', '.sbss'] or \
         'object' in type_flag or \
         symbol.startswith('__RTTI__') or \
         ('$' in symbol and not symbol.startswith('.')):
        globals_data.append({'parsed': entry})
    elif symbol in ['.data', '.bss', '.sdata', '.sbss', '.text'] or type_flag == '1':
        sections.append({'parsed': entry})
    else:
        sections.append({'parsed': entry})

def extract_all_for_object(map_file, object_file):
    """Extract comprehensive information for a specific object file (strict match)."""
    functions = []
    globals_data = []
    sections = []

    try:
        with open(map_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                line_stripped = line.strip()

                if (line_stripped.endswith(f"\t{object_file}") or
                    line_stripped.endswith(f" {object_file}") or
                    f"found in {object_file}" in line_stripped):
                    if "found in" in line_stripped:
                        parsed = _parse_en_found_in(line_stripped)
                    else:
                        parsed = _parse_pal_line(line_stripped)
                    _categorize_entry(parsed, functions, globals_data, sections)

                if len(functions) + len(globals_data) + len(sections) >= 200:
                    break

    except Exception as e:
        return {'error': f"Failed to read {map_file}: {e}"}

    return {
        'functions': functions[:15],  # Limit each category
        'globals': globals_data[:15],
        'sections': sections[:10]
    }

def extract_all_for_module(map_file, object_file=None, source_file=None):
    """Extract comprehensive information for a module using object and/or source identifiers."""
    identifiers = [v for v in [object_file, source_file] if v]
    if not identifiers:
        return {'functions': [], 'globals': [], 'sections': []}

    functions = []
    globals_data = []
    sections = []

    try:
        with open(map_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                line_stripped = line.strip()
                if not line_stripped:
                    continue

                if not any(ident in line_stripped for ident in identifiers):
                    continue

                if "found in" in line_stripped:
                    parsed = _parse_en_found_in(line_stripped)
                else:
                    parsed = _parse_pal_line(line_stripped)

                _categorize_entry(parsed, functions, globals_data, sections)

                if len(functions) + len(globals_data) + len(sections) >= 200:
                    break

    except Exception as e:
        return {'error': f"Failed to read {map_file}: {e}"}

    return {
        'functions': functions[:15],
        'globals': globals_data[:15],
        'sections': sections[:10]
    }

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 extract_symbols.py <search_term> [context]")
        print("Examples:")
        print("  python3 extract_symbols.py pppMatrixXZY              # Function lookup")
        print("  python3 extract_symbols.py file.o                   # Everything for object")
        print("  python3 extract_symbols.py .data --section          # Section info")
        print("  python3 extract_symbols.py file.o --globals         # Globals in object")
        print("  python3 extract_symbols.py CMaterialEditor --globals # Globals containing term")
        return 1

    search_term = sys.argv[1]
    context = sys.argv[2] if len(sys.argv) > 2 else None

    repo_root = Path(__file__).resolve().parent.parent
    pal_map = repo_root / "orig/GCCP01/game.MAP"
    en_map = repo_root / "orig/GCCE01/game.MAP"

    # Determine search mode
    is_section_search = context == "--section"
    is_globals_search = context == "--globals"
    is_object_file = search_term.endswith('.o') and not is_section_search and not is_globals_search
    is_source_file = search_term.endswith(('.c', '.cpp', '.s')) and not is_section_search and not is_globals_search

    print(f"SYMBOL SEARCH: {search_term}")
    if is_section_search:
        print("Mode: Section Information")
    elif is_globals_search:
        print("Mode: Global Variables")
    elif is_object_file:
        print("Mode: Comprehensive Object File Analysis")
    elif context:
        print(f"Unit context: {context}")
    print("=" * 60)

    # Execute appropriate search based on mode
    if is_object_file:
        # Comprehensive object file analysis - both PAL and EN
        if pal_map.exists():
            print(f"\n📦 PAL Release Analysis ({search_term}):")
            all_info = extract_all_for_object(pal_map, search_term)

            if 'error' in all_info:
                print(f"  Error: {all_info['error']}")
            else:
                # Functions
                if all_info['functions']:
                    print(f"\n  ⚡ Functions ({len(all_info['functions'])}):")
                    for i, func in enumerate(all_info['functions'], 1):
                        p = func['parsed']
                        try:
                            size_bytes = int(p['size'], 16) if p['size'] != 'UNUSED' else 0
                        except:
                            size_bytes = 0
                        size_kb = f"{size_bytes}"
                        warn_build_mismatch()
                        print(f"    {i:2}. {p['symbol']} ({size_kb}b at {p['virtual_addr']})")

                # Global Variables
                if all_info['globals']:
                    print(f"\n  🌍 Global Variables ({len(all_info['globals'])}):")
                    for i, glob in enumerate(all_info['globals'], 1):
                        p = glob['parsed']
                        try:
                            size_bytes = int(p['size'], 16) if p['size'] != 'UNUSED' else 0
                        except:
                            size_bytes = 0
                        size_kb = f"{size_bytes:,}"
                        warn_build_mismatch()
                        print(f"    {i:2}. {p['symbol']} ({size_kb}b {p['type_flag']} at {p['virtual_addr']})")

                # Other Sections
                if all_info['sections']:
                    print(f"\n  📂 Other Sections ({len(all_info['sections'])}):")
                    for i, sect in enumerate(all_info['sections'], 1):
                        p = sect['parsed']
                        print(f"    {i:2}. {p['symbol']} (type: {p['type_flag']})")

                # Summary
                total_functions = len(all_info['functions'])
                total_globals = len(all_info['globals'])
                print(f"\n  📊 Summary: {total_functions} functions, {total_globals} globals")

        # EN Debug analysis too
        if en_map.exists():
            print(f"\n📦 EN Debug Analysis ({search_term}):")
            all_info_en = extract_all_for_object(en_map, search_term)

            if 'error' in all_info_en:
                print(f"  Error: {all_info_en['error']}")
            else:
                # Functions
                if all_info_en['functions']:
                    print(f"\n  ⚡ Functions ({len(all_info_en['functions'])}):")
                    for i, func in enumerate(all_info_en['functions'], 1):
                        p = func['parsed']
                        try:
                            size_bytes = int(p['size'], 16) if p['size'] != 'UNUSED' else 0
                        except:
                            size_bytes = 0
                        size_kb = f"{size_bytes}"
                        warn_build_mismatch()
                        print(f"    {i:2}. {p['symbol']} ({size_kb}b at {p['virtual_addr']})")

                # Global Variables
                if all_info_en['globals']:
                    print(f"\n  🌍 Global Variables ({len(all_info_en['globals'])}):")
                    for i, glob in enumerate(all_info_en['globals'], 1):
                        p = glob['parsed']
                        try:
                            size_bytes = int(p['size'], 16) if p['size'] != 'UNUSED' else 0
                        except:
                            size_bytes = 0
                        size_kb = f"{size_bytes}"
                        warn_build_mismatch()
                        print(f"    {i:2}. {p['symbol']} ({size_kb}b {p['type_flag']} at {p['virtual_addr']})")

                # Summary
                total_functions_en = len(all_info_en['functions'])
                total_globals_en = len(all_info_en['globals'])
                print(f"\n  📊 Summary: {total_functions_en} functions, {total_globals_en} globals")

    elif is_section_search:
        # Section information search - both PAL and EN
        if pal_map.exists():
            print(f"\n📂 PAL Release Section Info ({search_term}):")
            section_results = extract_section_info(pal_map, search_term)

            if section_results:
                for i, result in enumerate(section_results[:8], 1):
                    if 'error' in result:
                        print(f"  Error: {result['error']}")
                    elif result['type'] == 'section_header':
                        print(f"  📋 {result['content']}")
                    else:
                        print(f"  {i-1}. {result['content']}")
                        if result.get('parsed'):
                            p = result['parsed']
                            warn_build_mismatch()
                            print(f"     Size: {p['size']} bytes at {p['virtual_addr']} from {p['object_file']}")
            else:
                print("  No section info found")

        if en_map.exists():
            print(f"\n📂 EN Debug Section Info ({search_term}):")
            section_results_en = extract_section_info(en_map, search_term)

            if section_results_en:
                for i, result in enumerate(section_results_en[:8], 1):
                    if 'error' in result:
                        print(f"  Error: {result['error']}")
                    elif result['type'] == 'section_header':
                        print(f"  📋 {result['content']}")
                    else:
                        print(f"  {i-1}. {result['content']}")
                        if result.get('parsed'):
                            p = result['parsed']
                            warn_build_mismatch()
                            print(f"     Size: {p['size']} bytes at {p['virtual_addr']} from {p['object_file']}")
            else:
                print("  No section info found")

    elif is_globals_search:
        # Globals search - both PAL and EN
        if pal_map.exists():
            print(f"\n🌍 PAL Release Global Variables (containing '{search_term}'):")
            if search_term.endswith('.o'):
                globals_results = extract_globals_for_file(pal_map, search_term)
            else:
                # Search for globals containing the term
                globals_results = extract_symbols_for_function(pal_map, search_term)
                globals_results = [r for r in globals_results if r.get('parsed') and
                                 r['parsed'].get('section') in ['.data', '.bss', '.sdata']]

            if globals_results:
                for i, result in enumerate(globals_results[:8], 1):
                    if 'error' in result:
                        print(f"  Error: {result['error']}")
                    else:
                        print(f"  {i}. {result['content']}")
                        if result.get('parsed'):
                            p = result['parsed']
                            section = p.get('section', 'unknown')
                            size = p.get('size', 'unknown')
                            addr = p.get('virtual_addr', 'unknown')
                            warn_build_mismatch()
                            print(f"     {section} section: {size} bytes at {addr}")
            else:
                print("  No global variables found")

        if en_map.exists():
            print(f"\n🌍 EN Debug Global Variables (containing '{search_term}'):")
            if search_term.endswith('.o'):
                globals_results_en = extract_globals_for_file(en_map, search_term)
            else:
                # Search for globals containing the term
                globals_results_en = extract_symbols_for_function(en_map, search_term)
                globals_results_en = [r for r in globals_results_en if r.get('parsed') and
                                     r['parsed'].get('section') in ['.data', '.bss', '.sdata']]

            if globals_results_en:
                for i, result in enumerate(globals_results_en[:8], 1):
                    if 'error' in result:
                        print(f"  Error: {result['error']}")
                    else:
                        print(f"  {i}. {result['content']}")
                        if result.get('parsed'):
                            p = result['parsed']
                            section = p.get('section', 'unknown')
                            size = p.get('size', 'unknown')
                            addr = p.get('virtual_addr', 'unknown')
                            warn_build_mismatch()
                            print(f"     {section} section: {size} bytes at {addr}")
            else:
                print("  No global variables found")

    elif is_source_file:
        if pal_map.exists():
            print(f"\n📍 PAL Release Symbols (GCCP01):")
            all_info = extract_all_for_module(pal_map, source_file=search_term)
            if 'error' in all_info:
                print(f"  Error: {all_info['error']}")
            else:
                if all_info['functions']:
                    print(f"\n  ⚡ Functions ({len(all_info['functions'])}):")
                    for i, func in enumerate(all_info['functions'], 1):
                        p = func['parsed']
                        warn_build_mismatch()
                        print(f"    {i:2}. {p['symbol']} ({p['size']}b at {p['virtual_addr']})")
                if all_info['globals']:
                    print(f"\n  🌍 Global Variables ({len(all_info['globals'])}):")
                    for i, glob in enumerate(all_info['globals'], 1):
                        p = glob['parsed']
                        warn_build_mismatch()
                        print(f"    {i:2}. {p['symbol']} ({p['size']}b {p['type_flag']} at {p['virtual_addr']})")
                print(f"\n  📊 Summary: {len(all_info['functions'])} functions, {len(all_info['globals'])} globals")

        if en_map.exists():
            print(f"\n📍 EN Debug Symbols (GCCE01):")
            all_info_en = extract_all_for_module(en_map, source_file=search_term)
            if 'error' in all_info_en:
                print(f"  Error: {all_info_en['error']}")
            else:
                if all_info_en['functions']:
                    print(f"\n  ⚡ Functions ({len(all_info_en['functions'])}):")
                    for i, func in enumerate(all_info_en['functions'], 1):
                        p = func['parsed']
                        warn_build_mismatch()
                        print(f"    {i:2}. {p['symbol']} ({p['size']}b at {p['virtual_addr']})")
                if all_info_en['globals']:
                    print(f"\n  🌍 Global Variables ({len(all_info_en['globals'])}):")
                    for i, glob in enumerate(all_info_en['globals'], 1):
                        p = glob['parsed']
                        warn_build_mismatch()
                        print(f"    {i:2}. {p['symbol']} ({p['size']}b {p['type_flag']} at {p['virtual_addr']})")
                print(f"\n  📊 Summary: {len(all_info_en['functions'])} functions, {len(all_info_en['globals'])} globals")

    else:
        # Function search (original behavior)
        if pal_map.exists():
            print("\n📍 PAL Release Symbols (GCCP01):")
            pal_results = extract_symbols_for_function(pal_map, search_term)

            if pal_results:
                for i, result in enumerate(pal_results[:5], 1):  # Limit to 5 results
                    if 'error' in result:
                        print(f"  Error: {result['error']}")
                    else:
                        print(f"  {i}. Line {result['line']}: {result['content']}")
                        if result['parsed'] and result['parsed']['address']:
                            parsed = result['parsed']
                            warn_build_mismatch()
                            print(f"     Address: {parsed['address']}, Size: {parsed['size']}, Section: {parsed['section']}")
            else:
                print("  No matches found")

        # Search EN MAP
        if en_map.exists():
            print("\n📍 EN Debug Symbols (GCCE01):")
            en_results = extract_symbols_for_function(en_map, search_term)

            if en_results:
                for i, result in enumerate(en_results[:5], 1):  # Limit to 5 results
                    if 'error' in result:
                        print(f"  Error: {result['error']}")
                    else:
                        print(f"  {i}. Line {result['line']}: {result['content']}")
                        if result['parsed'] and result['parsed']['address']:
                            parsed = result['parsed']
                            warn_build_mismatch()
                            print(f"     Address: {parsed['address']}, Size: {parsed['size']}, Section: {parsed['section']}")
            else:
                print("  No matches found")

    # Unit context search (for function mode only)
    if context and not is_section_search and not is_globals_search:
        print(f"\n📂 Unit Context ({context}):")
        if pal_map.exists():
            unit_results = extract_symbols_for_unit(pal_map, context)
            if unit_results[:3]:  # Show first 3 unit-related symbols
                for result in unit_results[:3]:
                    if 'error' not in result:
                        print(f"  {result['content']} (pattern: {result.get('pattern_match', 'unknown')})")

    # Keep the summary note too (this is not "before every instance", but it's still useful as a final reminder)
    print("\n⚠️  Note: Addresses and sizes are from a different build and may not match!")
    return 0

if __name__ == "__main__":
    exit(main())
