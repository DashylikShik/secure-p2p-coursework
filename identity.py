"""Persistent Ed25519 identity for the educational P2P node.

canonical_encode(public_key) := the 32 raw bytes of an Ed25519 public key.
NodeID := SHA-256(canonical_encode(public_key)).

A PRIVATE key is saved in identity.pem under a caller-specified state dir.
Never commit this directory, print the key, or send it over the network.
"""
from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

KEY_FILENAME = 'identity.pem'
PUBLIC_KEY_BYTES = 32
NODE_ID_BYTES = 32


class IdentityFileError(ValueError):
    """The stored identity key is damaged, unsupported or unreadable."""


def canonical_encode(public_key_bytes: bytes) -> bytes:
    """Canonical wire encoding: Ed25519 Raw public key, exactly 32 bytes.

    Our protocol v1 currently supports only Ed25519 identity keys.
    Since both algorithm and size are fixed, Raw encoding is unambiguous.
    """
    if not isinstance(public_key_bytes, bytes) or len(public_key_bytes) != PUBLIC_KEY_BYTES:
        raise ValueError('Ed25519 public key must be 32 bytes')
    return public_key_bytes


def node_id_from_public_key(public_key_bytes: bytes) -> bytes:
    """Derive the full 256-bit NodeID, not a random or short ID."""
    return hashlib.sha256(canonical_encode(public_key_bytes)).digest()


def verify_node_id(node_id: bytes, public_key_bytes: bytes) -> bool:
    """Check the claimed NodeID against the presented identity public key."""
    if not isinstance(node_id, bytes) or len(node_id) != NODE_ID_BYTES:
        return False
    try:
        expected = node_id_from_public_key(public_key_bytes)
    except ValueError:
        return False
    return hmac.compare_digest(node_id, expected)


def verify_signature(public_key_bytes: bytes, data: bytes, signature: bytes) -> bool:
    """Check Ed25519 signature; do NOT accept the key as trusted by default."""
    try:
        canonical_encode(public_key_bytes)
        Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(signature, data)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


@dataclass(frozen=True, repr=False)
class Identity:
    # repr=False prevents private key material from appearing in repr().
    _private_key: Ed25519PrivateKey = field(repr=False)
    created: bool = False

    @property
    def public_key_bytes(self) -> bytes:
        return self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    @property
    def node_id(self) -> bytes:
        return node_id_from_public_key(self.public_key_bytes)

    def sign(self, message: bytes) -> bytes:
        """Useful for signed DHT records in the next course stage."""
        return self._private_key.sign(message)


def load_or_create_identity(state_dir: str | Path) -> Identity:
    """Generate a key ONCE; load the same key after every restart.

    Stores unencrypted PKCS8 PEM for this *local educational prototype*.
    Keep the state directory private and OUTSIDE the Git repository.
    If a stored key is malformed, raise instead of silently changing ID.
    """
    directory = Path(state_dir).expanduser()
    directory.mkdir(parents=True, exist_ok=True)
    key_path = directory / KEY_FILENAME

    if key_path.exists():
        return Identity(_read_private_key(key_path), created=False)

    new_private_key = Ed25519PrivateKey.generate()
    pem = new_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Exclusive creation protects against accidentally replacing an old key.
    try:
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return Identity(_read_private_key(key_path), created=False)

    try:
        with os.fdopen(fd, 'wb') as file:
            file.write(pem)
    except BaseException:
        key_path.unlink(missing_ok=True)
        raise
    return Identity(new_private_key, created=True)


def _read_private_key(path: Path) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except (ValueError, TypeError, OSError) as exc:
        raise IdentityFileError(f'Cannot load stored identity key at {path}') from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise IdentityFileError('Stored identity key is not Ed25519')
    return key
