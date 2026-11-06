#!/usr/bin/env python3
"""Reject Unicode bidirectional controls in project text files."""
from pathlib import Path

root = Path(__file__).resolve().parents[1]
controls = {chr(code) for code in (*range(0x202A, 0x202F), *range(0x2066, 0x206A))}
for path in root.rglob('*'):
    if path.suffix not in {'.kt', '.kts', '.xml', '.md', '.properties'} or 'build' in path.parts:
        continue
    for line_number, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
        if any(char in controls for char in line):
            raise SystemExit(f'Bidirectional control in {path}:{line_number}')
print('No bidirectional controls found')
