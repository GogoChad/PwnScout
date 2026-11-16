"""Bounded, read-only hex views of local files."""
from pathlib import Path


def read_hex_page(path, offset=0, rows=16, width=16):
    """Return a page of hex/ASCII rows. Offsets refer to file bytes, not VM addresses."""
    if not isinstance(offset, int) or offset < 0:
        raise ValueError('Offset must be a non-negative integer')
    if not (1 <= rows <= 128 and 1 <= width <= 32):
        raise ValueError('Invalid page size')
    path = Path(path)
    size = path.stat().st_size
    with path.open('rb') as stream:
        stream.seek(offset)
        data = stream.read(rows * width)
    result = []
    for pos in range(0, len(data), width):
        chunk = data[pos:pos + width]
        result.append({
            'offset': f'0x{offset + pos:08X}',
            'hex': ' '.join(f'{byte:02X}' for byte in chunk),
            'ascii': ''.join(chr(byte) if 32 <= byte <= 126 else '.' for byte in chunk),
        })
    return {'rows': result, 'offset': offset, 'file_size': size, 'next_offset': min(size, offset + len(data))}
