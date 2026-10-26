import hashlib


def _h(b):
    return hashlib.sha256(b).digest()


def leaf(data: bytes):
    return _h(b"\x00" + data)


def _node(a, b):
    return _h(b"\x01" + a + b)


def root(leaves):
    if not leaves:
        return _h(b"")
    level = list(leaves)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [_node(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def proof(leaves, index):
    """Sibling path (list of (hash, sibling_is_right))."""
    level = list(leaves)
    path = []
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        sib = index ^ 1
        path.append((level[sib], sib > index))
        level = [_node(level[i], level[i + 1]) for i in range(0, len(level), 2)]
        index //= 2
    return path


def verify(leaf_hash, path, expected_root):
    cur = leaf_hash
    for sib, sib_right in path:
        cur = _node(cur, sib) if sib_right else _node(sib, cur)
    return cur == expected_root
