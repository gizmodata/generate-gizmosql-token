from __future__ import annotations

import datetime
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


# Constants reused by integration tests
GIZMOSQL_USERNAME = "gizmosql_user"
GIZMOSQL_PASSWORD = "gizmosql_password"

JWT_ISSUER = "GizmoData LLC"
JWT_AUDIENCE = "GizmoSQL Server"


@pytest.fixture(scope="session")
def rsa_keypair(tmp_path_factory):
    """RSA keypair on disk. Private key signs JWTs; public key is given to the
    GizmoSQL server as the JWT signature verification cert."""
    key_dir = tmp_path_factory.mktemp("keys")
    private_path = key_dir / "private_key.pem"
    public_path = key_dir / "public_key.pem"

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    public_path.write_bytes(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return {"private": private_path, "public": public_path}


@pytest.fixture
def output_dir(tmp_path: Path) -> Path:
    out = tmp_path / "output"
    out.mkdir()
    return out


def _generate_self_signed_tls_cert(out_dir: Path) -> tuple[Path, Path]:
    """Mint a self-signed RSA cert + key for ``localhost`` so the GizmoSQL
    test server's Flight SQL endpoint is reachable over ``grpc+tls://`` —
    the previous Docker image baked this in; the bare server binary needs
    explicit cert files passed via ``--tls``."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = out_dir / "tls_cert.pem"
    key_path = out_dir / "tls_key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


@pytest.fixture(scope="session")
def gizmosql_server(rsa_keypair, tmp_path_factory):
    """Spin up GizmoSQL with TLS + JWT auth enabled, using the
    [`gizmosql`](https://pypi.org/project/gizmosql/) PyPI package's managed
    subprocess (no Docker required for the test fixture).

    The RSA *public* key from ``rsa_keypair`` is registered as the JWT
    signature verification cert via ``TOKEN_SIGNATURE_VERIFY_CERT_PATH``,
    so tokens generated locally with the matching private key (via
    ``generate_gizmosql_token``) will authenticate.
    """
    gizmosql = pytest.importorskip("gizmosql")

    tls_dir = tmp_path_factory.mktemp("tls")
    # Restrict directory access to the owner before writing the unencrypted
    # TLS key — the dir is short-lived and loopback-only, but on shared CI
    # runners the system tmp dir would otherwise be world-readable.
    tls_dir.chmod(0o700)
    tls_cert, tls_key = _generate_self_signed_tls_cert(tls_dir)

    with gizmosql.Server(
        username=GIZMOSQL_USERNAME,
        password=GIZMOSQL_PASSWORD,
        extra_args=["--tls", str(tls_cert), str(tls_key)],
        extra_env={
            "PRINT_QUERIES": "1",
            "TOKEN_ALLOWED_ISSUER": JWT_ISSUER,
            "TOKEN_ALLOWED_AUDIENCE": JWT_AUDIENCE,
            "TOKEN_SIGNATURE_VERIFY_CERT_PATH": str(rsa_keypair["public"]),
        },
    ) as srv:
        yield srv


@pytest.fixture(scope="session")
def gizmosql_uri(gizmosql_server) -> str:
    return f"grpc+tls://{gizmosql_server.host}:{gizmosql_server.port}"
