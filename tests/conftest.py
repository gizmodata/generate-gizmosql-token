from pathlib import Path
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


# Constants reused by integration tests
GIZMOSQL_PORT = 31337
GIZMOSQL_IMAGE = "gizmodata/gizmosql:latest"
GIZMOSQL_USERNAME = "gizmosql_user"
GIZMOSQL_PASSWORD = "gizmosql_password"
CONTAINER_NAME = "generate-gizmosql-token-test"

JWT_ISSUER = "GizmoData LLC"
JWT_AUDIENCE = "GizmoSQL Server"
JWT_VERIFY_CERT_CONTAINER_PATH = "/jwt_verify_pub.pem"


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


def _wait_for_container_log(
    container,
    timeout: int = 60,
    poll_interval: float = 1.0,
    ready_message: str = "GizmoSQL server - started",
) -> None:
    """Poll container logs until the ready message appears."""
    start = time.time()
    while time.time() - start < timeout:
        logs = container.logs().decode("utf-8", errors="replace")
        if ready_message in logs:
            return
        if container.status == "exited":
            raise RuntimeError(
                f"GizmoSQL container exited before becoming ready. Logs:\n{logs}"
            )
        time.sleep(poll_interval)
    raise TimeoutError(
        f"Container did not show '{ready_message}' within {timeout}s.\n"
        f"Last logs:\n{container.logs().decode('utf-8', errors='replace')}"
    )


@pytest.fixture(scope="session")
def gizmosql_server(rsa_keypair):
    """Spin up a GizmoSQL container with TLS + JWT auth enabled.

    The fixture mounts the RSA *public* key PEM into the container as the JWT
    signature verification cert. Tokens generated locally with the matching
    private key (via ``generate_gizmosql_token``) will authenticate.
    """
    docker = pytest.importorskip("docker")
    client = docker.from_env()

    # Best-effort cleanup of a leftover container from a previous interrupted run.
    try:
        old = client.containers.get(CONTAINER_NAME)
        old.remove(force=True)
    except Exception:
        pass

    container = client.containers.run(
        image=GIZMOSQL_IMAGE,
        name=CONTAINER_NAME,
        detach=True,
        remove=True,
        tty=True,
        init=True,
        ports={f"{GIZMOSQL_PORT}/tcp": GIZMOSQL_PORT},
        volumes={
            str(rsa_keypair["public"]): {
                "bind": JWT_VERIFY_CERT_CONTAINER_PATH,
                "mode": "ro",
            }
        },
        environment={
            "GIZMOSQL_USERNAME": GIZMOSQL_USERNAME,
            "GIZMOSQL_PASSWORD": GIZMOSQL_PASSWORD,
            "TLS_ENABLED": "1",
            "PRINT_QUERIES": "1",
            "DATABASE_FILENAME": ":memory:",
            "TOKEN_ALLOWED_ISSUER": JWT_ISSUER,
            "TOKEN_ALLOWED_AUDIENCE": JWT_AUDIENCE,
            "TOKEN_SIGNATURE_VERIFY_CERT_PATH": JWT_VERIFY_CERT_CONTAINER_PATH,
        },
        stdout=True,
        stderr=True,
    )

    try:
        _wait_for_container_log(container)
        yield container
    finally:
        try:
            container.stop(timeout=5)
        except Exception:
            pass


@pytest.fixture(scope="session")
def gizmosql_uri() -> str:
    return f"grpc+tls://localhost:{GIZMOSQL_PORT}"
