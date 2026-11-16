"""Shannon entropy metrics for ELF sections (a heuristic, not a malware detector)."""
from collections import Counter
from math import log2

MAX_SECTION_SAMPLE = 1024 * 1024  # Bound memory and processing to 1 MiB per section.


def shannon_entropy(data):
    """Return byte entropy in bits per byte, between 0 and 8."""
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((count / total) * log2(count / total) for count in counts.values())


def inspect_section_entropy(elf, max_sample=MAX_SECTION_SAMPLE):
    """Inspect file-backed section bytes; sampling is clearly reported."""
    if max_sample < 1:
        raise ValueError('max_sample must be positive')
    results = []
    fileobj = elf.stream
    for section in elf.iter_sections():
        header = section.header
        size = int(header['sh_size'])
        typ = str(header['sh_type'])
        if typ == 'SHT_NOBITS':
            results.append({'name': section.name or '(unnamed)', 'entropy': None,
                            'sampled_bytes': 0, 'section_bytes': size, 'status': 'No file bytes (NOBITS)'})
            continue
        if size == 0:
            results.append({'name': section.name or '(unnamed)', 'entropy': None,
                            'sampled_bytes': 0, 'section_bytes': 0, 'status': 'Empty'})
            continue
        sample_len = min(size, max_sample)
        position = fileobj.tell()
        try:
            fileobj.seek(int(header['sh_offset']))
            data = fileobj.read(sample_len)
        finally:
            fileobj.seek(position)
        results.append({
            'name': section.name or '(unnamed)',
            'entropy': round(shannon_entropy(data), 3) if data else None,
            'sampled_bytes': len(data), 'section_bytes': size,
            'status': 'Sampled' if sample_len < size else ('Truncated' if len(data) < sample_len else 'Complete'),
        })
    return results
