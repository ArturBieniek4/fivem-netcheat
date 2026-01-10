# JOAAT hash
def RAGEHash(key: str) -> int:
    h = 0
    for ch in key.encode("utf-8"):
        h = (h + ch) & 0xFFFFFFFF
        h = (h + (h << 10)) & 0xFFFFFFFF
        h ^= (h >> 6)

    h = (h + (h << 3)) & 0xFFFFFFFF
    h ^= (h >> 11)
    h = (h + (h << 15)) & 0xFFFFFFFF
    return h & 0xFFFFFFFF

