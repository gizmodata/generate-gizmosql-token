"""End-to-end tests: generate a JWT with our utility, then authenticate against
a real GizmoSQL container running with JWT auth enabled.

Requires Docker. Skip with: pytest -m "not integration"
"""
from __future__ import annotations

import pytest

from generate_gizmosql_token.main import generate_gizmosql_token

pytestmark = pytest.mark.integration

# Must match the values configured for the server in conftest.gizmosql_server
JWT_ISSUER = "GizmoData LLC"
JWT_AUDIENCE = "GizmoSQL Server"


def _generate_token(
    rsa_keypair,
    output_dir,
    *,
    subject: str = "tester@gizmodata.com",
    role: str = "admin",
    lifetime_seconds: int = 3600,
    issuer: str = JWT_ISSUER,
    audience: str = JWT_AUDIENCE,
    catalog_access=None,
) -> str:
    return generate_gizmosql_token(
        issuer=issuer,
        audience=audience,
        subject=subject,
        role=role,
        token_lifetime_seconds=lifetime_seconds,
        output_file_format=str(output_dir / "tok_{subject}_{role}.jwt"),
        private_key_file=str(rsa_keypair["private"]),
        catalog_access=catalog_access,
    )


def _connect(uri, password):
    gizmosql = pytest.importorskip("adbc_driver_gizmosql.dbapi")
    return gizmosql.connect(
        uri,
        username="token",
        password=password,
        tls_skip_verify=True,
    )


def test_jwt_auth_succeeds(gizmosql_server, gizmosql_uri, rsa_keypair, output_dir):
    token = _generate_token(rsa_keypair, output_dir)

    with _connect(gizmosql_uri, token) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 AS value")
            table = cur.fetch_arrow_table()
            assert table.num_rows == 1
            assert table.column("value")[0].as_py() == 1


def test_jwt_auth_returns_gizmosql_version(
    gizmosql_server, gizmosql_uri, rsa_keypair, output_dir
):
    token = _generate_token(rsa_keypair, output_dir, role="readonly")

    with _connect(gizmosql_uri, token) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT GIZMOSQL_VERSION() AS version")
            table = cur.fetch_arrow_table()
            version = table.column("version")[0].as_py()
            assert isinstance(version, str) and version


def test_garbage_token_is_rejected(gizmosql_server, gizmosql_uri):
    with pytest.raises(Exception):
        with _connect(gizmosql_uri, "this-is-not-a-jwt") as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
                cur.fetch_arrow_table()


def test_expired_token_is_rejected(
    gizmosql_server, gizmosql_uri, rsa_keypair, output_dir
):
    token = _generate_token(rsa_keypair, output_dir, lifetime_seconds=-60)

    with pytest.raises(Exception):
        with _connect(gizmosql_uri, token) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
                cur.fetch_arrow_table()


def test_wrong_issuer_is_rejected(
    gizmosql_server, gizmosql_uri, rsa_keypair, output_dir
):
    token = _generate_token(rsa_keypair, output_dir, issuer="Some Other Issuer")

    with pytest.raises(Exception):
        with _connect(gizmosql_uri, token) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
                cur.fetch_arrow_table()


def test_wrong_audience_is_rejected(
    gizmosql_server, gizmosql_uri, rsa_keypair, output_dir
):
    token = _generate_token(rsa_keypair, output_dir, audience="Some Other Audience")

    with pytest.raises(Exception):
        with _connect(gizmosql_uri, token) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
                cur.fetch_arrow_table()


def test_token_signed_with_different_key_is_rejected(
    gizmosql_server, gizmosql_uri, output_dir, tmp_path
):
    """A JWT signed with a key the server doesn't trust must be rejected."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa

    other_priv = tmp_path / "other_priv.pem"
    other_key = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other_priv.write_bytes(
        other_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    bogus_token = generate_gizmosql_token(
        issuer=JWT_ISSUER,
        audience=JWT_AUDIENCE,
        subject="tester@gizmodata.com",
        role="admin",
        token_lifetime_seconds=3600,
        output_file_format=str(output_dir / "bogus_{subject}.jwt"),
        private_key_file=str(other_priv),
    )

    with pytest.raises(Exception):
        with _connect(gizmosql_uri, bogus_token) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
                cur.fetch_arrow_table()
