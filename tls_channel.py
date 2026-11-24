"""Stage 4.1: TLS 1.3 mutual authentication bound to the existing Ed25519 NodeID.

An explicitly trusted, offline training CA signs leaf certificates.  The CA
is NOT a node directory; normal DHT lookup does not use it.  This module does
NOT yet turn the existing DHTNode RPC connections into TLS connections.
"""
from __future__ import annotations

import hmac
import os
import ssl
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from identity import Identity, node_id_from_public_key


class PeerIdentityError(ValueError):
    """The verified certificate is not the expected P2P node identity."""


@dataclass(frozen=True)
class TlsCredentials:
    cert_path: Path
    key_path: Path
    ca_path: Path


def _save_private(path: Path, private_key: Ed25519PrivateKey) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    # Do not overwrite pre-existing CA keys. Windows file protection also
    # depends on the user's ACL of the containing directory.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(pem)


def _load_ed25519_private(path: Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError('TLS demo CA must use Ed25519')
    return key


def ensure_demo_ca(directory: str | Path) -> tuple[Path, Ed25519PrivateKey]:
    """Create/reuse an EXPLICIT test trust anchor outside the Git checkout.

    The self-signed CA is trusted ONLY because its certificate is explicitly
    provisioned to both endpoints; self-signed peer certs are never accepted.
    """
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    key_file = directory / 'demo_ca_private.pem'
    cert_file = directory / 'demo_ca_cert.pem'
    if key_file.exists() != cert_file.exists():
        raise ValueError('Incomplete demo CA state; do not silently change trust anchor')
    if key_file.exists():
        key = _load_ed25519_private(key_file)
        cert = x509.load_pem_x509_certificate(cert_file.read_bytes())
        if cert.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        ) != key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw):
            raise ValueError('CA key and certificate mismatch')
        if datetime.now(timezone.utc) >= cert.not_valid_after_utc:
            raise ValueError('Demo CA expired; re-provision manually')
        return cert_file, key

    key = Ed25519PrivateKey.generate()
    now = datetime.now(timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'P2P Coursework DEMO Trust Root')])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False,
            key_encipherment=False, data_encipherment=False, key_agreement=False,
            key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, algorithm=None)
    )
    _save_private(key_file, key)
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert_file, key


def issue_demo_leaf(identity: Identity, identity_key_path: str | Path,
                    name: str, ca_file: str | Path,
                    ca_key: Ed25519PrivateKey,
                    cert_file: str | Path) -> TlsCredentials:
    """Issue CA-signed TLS certificate with the SAME Ed25519 key as NodeID."""
    key_path = Path(identity_key_path)
    cert_path = Path(cert_file)
    ca_path = Path(ca_file)
    if not key_path.is_file() or not ca_path.is_file():
        raise FileNotFoundError('Identity private key / trust root is missing')
    actual_key = _load_ed25519_private(key_path)
    actual_raw = actual_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if not hmac.compare_digest(actual_raw, identity.public_key_bytes):
        raise ValueError('TLS certificate cannot use a different identity private key')
    ca_cert = x509.load_pem_x509_certificate(ca_path.read_bytes())
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f'P2P Node {name}')]))
        .issuer_name(ca_cert.subject)
        .public_key(actual_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=7))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
            key_encipherment=False, data_encipherment=False, key_agreement=False,
            key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH,
        ]), critical=False)
        .add_extension(x509.SubjectAlternativeName([
            x509.UniformResourceIdentifier(f'urn:p2p-coursework:nodeid:{identity.node_id.hex()}'),
        ]), critical=False)
        .sign(ca_key, algorithm=None)
    )
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return TlsCredentials(cert_path, key_path, ca_path)


def _base_context(server: bool, credentials: TlsCredentials) -> ssl.SSLContext:
    if not ssl.HAS_TLSv1_3:
        raise RuntimeError('OpenSSL/Python does not support TLS 1.3')
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server else ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    # Explicit trust root + verified certificate chain: never CERT_NONE.
    context.verify_mode = ssl.CERT_REQUIRED
    if not server:
        # NodeID pin is the authenticated application name. This is NOT a
        # relaxation of certificate-chain verification (CERT_REQUIRED remains).
        context.check_hostname = False
    context.load_verify_locations(cafile=str(credentials.ca_path))
    context.load_cert_chain(certfile=str(credentials.cert_path), keyfile=str(credentials.key_path))
    # No session tickets/early-data use in this educational prototype.
    context.options |= ssl.OP_NO_TICKET
    return context


def server_tls_context(credentials: TlsCredentials) -> ssl.SSLContext:
    return _base_context(True, credentials)


def client_tls_context(credentials: TlsCredentials) -> ssl.SSLContext:
    return _base_context(False, credentials)


def check_local_tls_identity(credentials: TlsCredentials, expected_node_id: bytes) -> None:
    """Fail startup when local TLS leaf certificate belongs to a different node."""
    cert = x509.load_pem_x509_certificate(Path(credentials.cert_path).read_bytes())
    key = cert.public_key()
    if not isinstance(key, Ed25519PublicKey):
        raise PeerIdentityError('Local TLS certificate must use Ed25519')
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if not hmac.compare_digest(node_id_from_public_key(raw), expected_node_id):
        raise PeerIdentityError('Local TLS certificate does not belong to DHT NodeID')


def verified_certificate_identity(tls_sock: ssl.SSLSocket) -> tuple[bytes, bytes]:
    """Read TLS 1.3 peer identity only AFTER CERT_REQUIRED chain verification.

    Inbound seed discovery cannot pin an unknown caller in advance. The
    certificate still must chain to the explicitly configured CA; its
    Ed25519 public key is bound to the claimed NodeID in the RPC envelope.
    """
    if tls_sock.version() != 'TLSv1.3':
        raise PeerIdentityError('TLS 1.3 required')
    der = tls_sock.getpeercert(binary_form=True)
    if not der:
        raise PeerIdentityError('Missing verified peer certificate')
    cert = x509.load_der_x509_certificate(der)
    key = cert.public_key()
    if not isinstance(key, Ed25519PublicKey):
        raise PeerIdentityError('Peer identity key must be Ed25519')
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    actual_id = node_id_from_public_key(raw)
    try:
        sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        uris = sans.get_values_for_type(x509.UniformResourceIdentifier)
        if f'urn:p2p-coursework:nodeid:{actual_id.hex()}' not in uris:
            raise PeerIdentityError('Certificate NodeID SAN does not match key')
    except x509.ExtensionNotFound as exc:
        raise PeerIdentityError('Missing certificate NodeID SAN') from exc
    return actual_id, raw


def verify_expected_peer(tls_sock: ssl.SSLSocket, expected_node_id: bytes,
                         expected_public_key: bytes | None = None) -> bytes:
    """After CA-verified TLS handshake, bind presented peer key to NodeID.

    Call this BEFORE interpreting or responding to any application frame.
    """
    if not isinstance(expected_node_id, bytes) or len(expected_node_id) != 32:
        raise ValueError('expected NodeID must be 32 bytes')
    actual_id, raw_key = verified_certificate_identity(tls_sock)
    if not hmac.compare_digest(actual_id, expected_node_id):
        raise PeerIdentityError('TLS certificate public key does not match expected NodeID')
    if expected_public_key is not None and not hmac.compare_digest(raw_key, expected_public_key):
        raise PeerIdentityError('TLS certificate public key does not match pinned public key')
    return actual_id
