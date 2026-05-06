import datetime

import jwt
import pytest
from click.testing import CliRunner

from generate_gizmosql_token.main import (
    click_generate_gizmosql_token,
    generate_gizmosql_token,
)


ISSUER = "GizmoData LLC"
AUDIENCE = "GizmoSQL Server"
SUBJECT = "tester@gizmodata.com"
ROLE = "admin"


def _decode(token: str, public_key_path) -> dict:
    public_key = public_key_path.read_bytes()
    return jwt.decode(
        token,
        public_key,
        algorithms=["RS256"],
        audience=AUDIENCE,
        issuer=ISSUER,
    )


def test_generates_valid_token(rsa_keypair, output_dir):
    output_format = str(output_dir / "token_{subject}.jwt")

    token = generate_gizmosql_token(
        issuer=ISSUER,
        audience=AUDIENCE,
        subject=SUBJECT,
        role=ROLE,
        token_lifetime_seconds=3600,
        output_file_format=output_format,
        private_key_file=str(rsa_keypair["private"]),
    )

    claims = _decode(token, rsa_keypair["public"])
    assert claims["iss"] == ISSUER
    assert claims["aud"] == AUDIENCE
    assert claims["sub"] == SUBJECT
    assert claims["role"] == ROLE
    assert "jti" in claims
    assert claims["exp"] - claims["iat"] == 3600
    assert "catalog_access" not in claims


def test_writes_token_to_file(rsa_keypair, output_dir):
    output_format = str(output_dir / "token_{subject}_{role}.jwt")

    token = generate_gizmosql_token(
        issuer=ISSUER,
        audience=AUDIENCE,
        subject=SUBJECT,
        role=ROLE,
        token_lifetime_seconds=60,
        output_file_format=output_format,
        private_key_file=str(rsa_keypair["private"]),
    )

    expected = output_dir / f"token_{SUBJECT.lower()}_{ROLE.lower()}.jwt"
    assert expected.read_text() == token


def test_output_filename_lowercases_and_replaces_spaces(rsa_keypair, output_dir):
    output_format = str(output_dir / "token_{issuer}_{audience}.jwt")

    generate_gizmosql_token(
        issuer=ISSUER,
        audience=AUDIENCE,
        subject=SUBJECT,
        role=ROLE,
        token_lifetime_seconds=60,
        output_file_format=output_format,
        private_key_file=str(rsa_keypair["private"]),
    )

    expected = output_dir / "token_gizmodata_llc_gizmosql_server.jwt"
    assert expected.exists()


def test_catalog_access_included_in_token(rsa_keypair, output_dir):
    rules = [
        {"catalog": "memory", "access": "write"},
        {"catalog": "*", "access": "read"},
    ]
    token = generate_gizmosql_token(
        issuer=ISSUER,
        audience=AUDIENCE,
        subject=SUBJECT,
        role="user",
        token_lifetime_seconds=60,
        output_file_format=str(output_dir / "t_{subject}.jwt"),
        private_key_file=str(rsa_keypair["private"]),
        catalog_access=rules,
    )

    claims = _decode(token, rsa_keypair["public"])
    assert claims["catalog_access"] == rules


def test_token_expires_in_the_past_is_rejected(rsa_keypair, output_dir):
    token = generate_gizmosql_token(
        issuer=ISSUER,
        audience=AUDIENCE,
        subject=SUBJECT,
        role=ROLE,
        token_lifetime_seconds=-1,
        output_file_format=str(output_dir / "t_{subject}.jwt"),
        private_key_file=str(rsa_keypair["private"]),
    )

    with pytest.raises(jwt.ExpiredSignatureError):
        _decode(token, rsa_keypair["public"])


def test_wrong_public_key_fails_verification(rsa_keypair, output_dir, tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa

    other_key = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other_pub = tmp_path / "other_public.pem"
    other_pub.write_bytes(
        other_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    token = generate_gizmosql_token(
        issuer=ISSUER,
        audience=AUDIENCE,
        subject=SUBJECT,
        role=ROLE,
        token_lifetime_seconds=60,
        output_file_format=str(output_dir / "t_{subject}.jwt"),
        private_key_file=str(rsa_keypair["private"]),
    )

    with pytest.raises(jwt.InvalidSignatureError):
        _decode(token, other_pub)


def test_cli_generates_token(rsa_keypair, output_dir):
    output_format = str(output_dir / "cli_{subject}.jwt")
    runner = CliRunner()
    result = runner.invoke(
        click_generate_gizmosql_token,
        [
            "--issuer", ISSUER,
            "--audience", AUDIENCE,
            "--subject", SUBJECT,
            "--role", ROLE,
            "--token-lifetime-seconds", "60",
            "--output-file-format", output_format,
            "--private-key-file", str(rsa_keypair["private"]),
        ],
    )

    assert result.exit_code == 0, result.output
    expected = output_dir / f"cli_{SUBJECT.lower()}.jwt"
    assert expected.exists()
    claims = _decode(expected.read_text(), rsa_keypair["public"])
    assert claims["sub"] == SUBJECT


def test_cli_with_catalog_access(rsa_keypair, output_dir):
    output_format = str(output_dir / "cli_cat_{subject}.jwt")
    runner = CliRunner()
    result = runner.invoke(
        click_generate_gizmosql_token,
        [
            "--issuer", ISSUER,
            "--audience", AUDIENCE,
            "--subject", SUBJECT,
            "--role", "user",
            "--token-lifetime-seconds", "60",
            "--output-file-format", output_format,
            "--private-key-file", str(rsa_keypair["private"]),
            "--catalog-access",
            '[{"catalog":"memory","access":"write"},{"catalog":"*","access":"none"}]',
        ],
    )

    assert result.exit_code == 0, result.output
    expected = output_dir / f"cli_cat_{SUBJECT.lower()}.jwt"
    claims = _decode(expected.read_text(), rsa_keypair["public"])
    assert claims["catalog_access"] == [
        {"catalog": "memory", "access": "write"},
        {"catalog": "*", "access": "none"},
    ]


@pytest.mark.parametrize(
    "bad_value,expected_msg",
    [
        ("not-json", "Invalid JSON"),
        ('{"catalog":"x","access":"read"}', "must be a JSON array"),
        ('["a string"]', "must be an object"),
        ('[{"catalog":"x"}]', "must have 'catalog' and 'access'"),
        ('[{"catalog":"x","access":"bogus"}]', "Invalid access value"),
    ],
)
def test_cli_invalid_catalog_access(rsa_keypair, output_dir, bad_value, expected_msg):
    runner = CliRunner()
    result = runner.invoke(
        click_generate_gizmosql_token,
        [
            "--subject", SUBJECT,
            "--role", "user",
            "--token-lifetime-seconds", "60",
            "--output-file-format", str(output_dir / "t_{subject}.jwt"),
            "--private-key-file", str(rsa_keypair["private"]),
            "--catalog-access", bad_value,
        ],
    )

    assert result.exit_code != 0
    assert expected_msg in result.output


def test_missing_private_key_raises(output_dir, tmp_path):
    with pytest.raises(FileNotFoundError):
        generate_gizmosql_token(
            issuer=ISSUER,
            audience=AUDIENCE,
            subject=SUBJECT,
            role=ROLE,
            token_lifetime_seconds=60,
            output_file_format=str(output_dir / "t_{subject}.jwt"),
            private_key_file=str(tmp_path / "does_not_exist.pem"),
        )
