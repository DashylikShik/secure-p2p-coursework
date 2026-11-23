"""Kademlia: XOR distance and bounded LRU-like k-buckets.

Stage 2, part 1: a standalone learning module; no networking or identity yet.
Node IDs must be 32-byte SHA-256 digests in the finished project.
"""
from collections import OrderedDict
from dataclasses import dataclass
from typing import Callable


NODE_ID_BYTES = 32


def validate_node_id(node_id: bytes) -> None:
    """Reject malformed IDs early; the network protocol will use 256-bit IDs."""
    if not isinstance(node_id, bytes) or len(node_id) != NODE_ID_BYTES:
        raise ValueError("NodeID must contain exactly 32 bytes")


def xor_distance(left: bytes, right: bytes) -> int:
    """Kademlia XOR metric: identical IDs have distance zero."""
    validate_node_id(left)
    validate_node_id(right)
    return int.from_bytes(left, 'big') ^ int.from_bytes(right, 'big')


def bucket_index(own_id: bytes, other_id: bytes) -> int | None:
    """0..255 for a contact; None for the local node itself."""
    dist = xor_distance(own_id, other_id)
    return dist.bit_length() - 1 if dist else None


@dataclass(frozen=True)
class Contact:
    node_id: bytes
    host: str
    port: int

    def __post_init__(self) -> None:
        validate_node_id(self.node_id)
        if not isinstance(self.host, str) or not self.host:
            raise ValueError("host must be a nonempty string")
        if isinstance(self.port, bool) or not isinstance(self.port, int) or not (1 <= self.port <= 65535):
            raise ValueError("port must be an integer from 1 to 65535")

    @property
    def short_id(self) -> str:
        return self.node_id.hex()[:12]


class RoutingTable:
    """Each bucket keeps at most k contacts, oldest first (LRU-like).

    This is NOT a complete peer directory. A network lookup will query
    other nodes; only known contacts are kept here.
    """

    def __init__(self, own_id: bytes, k: int = 3):
        validate_node_id(own_id)
        if isinstance(k, bool) or not isinstance(k, int) or k < 1:
            raise ValueError("k must be a positive integer")
        self.own_id = own_id
        self.k = k
        self._buckets: dict[int, OrderedDict[bytes, Contact]] = {}

    def observe(self, contact: Contact,
                ping_oldest: Callable[[Contact], bool] | None = None) -> str:
        """Observe a contact; call ping_oldest before replacing a full bucket.

        Return: ignored_self, added, updated, needs_ping, kept_old, replaced.
        For the real network the callback will send a PING RPC. It MUST NOT
        be replaced with an assumption that the old contact is dead.
        """
        if not isinstance(contact, Contact):
            raise TypeError("contact must be Contact")
        index = bucket_index(self.own_id, contact.node_id)
        if index is None:
            return 'ignored_self'
        bucket = self._buckets.setdefault(index, OrderedDict())

        if contact.node_id in bucket:
            bucket[contact.node_id] = contact
            bucket.move_to_end(contact.node_id)
            return 'updated'

        if len(bucket) < self.k:
            bucket[contact.node_id] = contact
            return 'added'

        oldest_id, oldest_contact = next(iter(bucket.items()))
        if ping_oldest is None:
            return 'needs_ping'
        if ping_oldest(oldest_contact):
            bucket.move_to_end(oldest_id)
            return 'kept_old'

        del bucket[oldest_id]
        bucket[contact.node_id] = contact
        return 'replaced'

    def nearest(self, target_id: bytes, limit: int = 3) -> list[Contact]:
        """Return closest KNOWN contacts; this is not an iterative lookup."""
        validate_node_id(target_id)
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be positive")
        contacts = [contact for bucket in self._buckets.values()
                    for contact in bucket.values()]
        contacts.sort(key=lambda contact: (xor_distance(contact.node_id, target_id), contact.node_id))
        return contacts[:limit]

    def bucket_contents(self) -> dict[int, list[Contact]]:
        """Snapshot for diagnostics, not a global registry of the network."""
        return {index: list(bucket.values()) for index, bucket in sorted(self._buckets.items())}

    def size(self) -> int:
        return sum(len(bucket) for bucket in self._buckets.values())
