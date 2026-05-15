import re
import sys


# ----------------------------------------------------------------------
# Protobuf parsing stuff
# ----------------------------------------------------------------------


def _read_varint(data: bytes, pos: int) -> tuple[int, int]:
    """Decode a protobuf varint."""
    result = 0
    shift = 0
    while True:
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if (b & 0x80) == 0:
            return result, pos


def _read_bytes_field(data: bytes, pos: int) -> tuple[bytes, int]:
    """Read a length‑delimited field."""
    length, pos = _read_varint(data, pos)
    end = pos + length
    return data[pos:end], end


def _parse_domain(data: bytes) -> tuple[int | None, str | None]:
    """Parse a Domain submessage → (type, value)."""
    domain_type = None
    value = None
    pos = 0
    while pos < len(data):
        tag_byte = data[pos]
        pos += 1
        field_num = tag_byte >> 3
        wire_type = tag_byte & 0x07

        if wire_type == 0:  # varint → type
            val, pos = _read_varint(data, pos)
            if field_num == 1:
                domain_type = val
        elif wire_type == 2:  # length‑delimited → value
            bytes_val, pos = _read_bytes_field(data, pos)
            if field_num == 2:
                value = bytes_val.decode("utf-8")
        else:
            bytes_val, pos = _read_bytes_field(data, pos)
            value = bytes_val.decode("utf-8")
            # skip unknown wire types
            if wire_type == 1:
                pos += 8
            elif wire_type == 5:
                pos += 4
            else:
                raise ValueError(f"Unsupported wire type {wire_type}")
    return domain_type, value


def _parse_geosite_entry(data: bytes) -> tuple[str, list[tuple[int, str]]]:
    """Parse one GeoSite message → (country_code, list_of_(type, value))."""
    country_code = None
    domains = []
    pos = 0
    while pos < len(data):
        tag_byte = data[pos]
        pos += 1
        field_num = tag_byte >> 3
        wire_type = tag_byte & 0x07
        if wire_type != 2:
            # skip non‑length‑delimited fields
            if wire_type == 0:
                _, pos = _read_varint(data, pos)
            elif wire_type == 1:
                pos += 8
            elif wire_type == 5:
                pos += 4
            continue

        bytes_val, pos = _read_bytes_field(data, pos)
        if field_num == 1:  # country_code
            country_code = bytes_val.decode("utf-8")
        elif field_num == 2:  # domain (repeated)
            d_type, d_val = _parse_domain(bytes_val)
            if d_type is not None and d_val is not None:
                domains.append((d_type, d_val))
    if country_code is None:
        raise ValueError("Missing country_code in GeoSite entry")
    return country_code.lower(), domains


class GeoSiteChecker:
    _MATCHERS = {
        0: lambda domain, pattern: pattern in domain,
        1: lambda domain, pattern: re.search(pattern, domain) is not None,
        2: lambda domain, root_domain: re.match(
            r"^(.*\.)?{}$".format(re.escape(root_domain)), domain, re.IGNORECASE
        ),
        3: lambda domain, pattern: domain == pattern,
    }

    def __init__(self, file_path: str):
        self._rules: dict[str, list[tuple[int, str]]] = {}
        with open(file_path, "rb") as f:
            data = f.read()

        pos = 0
        while pos < len(data):
            # Each entry starts with tag 0x0A (field 1, wire type 2)
            if data[pos] != 0x0A:
                raise ValueError(f"Expected 0x0A at offset {pos}, got {data[pos]:02X}")
            pos += 1
            entry_len, pos = _read_varint(data, pos)
            entry_data = data[pos : pos + entry_len]
            pos += entry_len

            country, domains = _parse_geosite_entry(entry_data)
            # Keep only the first occurrence if duplicates exist
            if country not in self._rules:
                self._rules[country] = domains

    def categories(self) -> list[str]:
        return sorted(self._rules.keys())

    def check(self, domain: str, category: str) -> bool:
        category = category.lower()
        if category not in self._rules:
            return False
        domain_lower = domain.lower()
        for typ, pattern in self._rules[category]:
            matcher = self._MATCHERS.get(typ)
            if matcher is None:
                continue

            if typ == 1:  # regex
                if matcher(domain_lower, pattern):
                    return True
            else:
                if matcher(domain_lower, pattern.lower()):
                    return True
        return False


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Check if a domain belongs to a specific category in a geosite.dat file"
    )
    parser.add_argument("dat_file", help="Path to the geosite.dat file")
    parser.add_argument("category", help="Category to check against")
    parser.add_argument("domain", help="Domain name to check")

    args = parser.parse_args()

    dat_file = args.dat_file
    category = args.category
    domain = args.domain

    try:
        checker = GeoSiteChecker(dat_file)
    except Exception as e:
        print(f"Failed to load {dat_file}: {e}")
        sys.exit(1)

    if checker.check(domain, category):
        print(f"✅ '{domain}' belongs to category '{category}'")
    else:
        print(f"❌ '{domain}' does NOT belong to category '{category}'")
