import datetime
import uuid

import click
import jwt


def generate_gizmosql_token(issuer: str,
                            output_file_format: str,
                            private_key_file: str,
                            audience: str,
                            subject: str,
                            role: str,
                            token_lifetime_seconds: int,
                            algorithm: str = "RS256"):
    try:
        jti = str(uuid.uuid4())
        payload = dict(jti=jti,
                       aud=audience,
                       sub=subject,
                       iss=issuer,
                       )

        # Read the private key
        with open(private_key_file, "r") as key_file:
            private_key = key_file.read()

        # Add standard claims to the payload
        current_time = datetime.datetime.now(tz=datetime.UTC)
        payload.update({
            "iat": current_time,  # Issued at
            "exp": current_time + datetime.timedelta(seconds=token_lifetime_seconds),  # Expiration
            "nbf": current_time,  # Not before
            "role": role,  # Custom role claim
        })

        # Generate the JWT
        token = jwt.encode(payload, private_key, algorithm=algorithm)

        # Save the JWT to the specified file
        output_file = output_file_format.format(issuer=issuer.lower(),
                                                audience=audience.lower(),
                                                subject=subject.lower(),
                                                role=role.lower()
                                                ).replace(" ", "_")
        with open(output_file, "w") as jwt_file:
            jwt_file.write(token)

        print(f"JWT successfully generated and saved to:\n{output_file}")
        return token

    except Exception as e:
        print(f"Error generating JWT: {e}")
        raise


@click.command()
@click.option(
    "--issuer",
    type=str,
    default="GizmoData LLC",
    show_default=True,
    required=True,
    help="The JWT Token Issuer.",
)
@click.option(
    "--audience",
    type=str,
    default="GizmoSQL Server",
    show_default=True,
    required=True,
    help="The JWT Token Audience (e.g. the server validating the token).",
)
@click.option(
    "--subject",
    type=str,
    required=True,
    help="The subject name to issue the token to.",
)
@click.option(
    "--role",
    type=str,
    required=True,
    help="The value to assign to the role claim in the token.",
)
@click.option(
    "--token-lifetime-seconds",
    type=int,
    required=True,
    default=(60 * 60 * 24 * 30),  # 30 days
    show_default=True,
    help="The number of seconds the token should be valid for.",
)
@click.option(
    "--output-file-format",
    type=str,
    default="output/gizmosql_token_{issuer}_{audience}_{subject}_{role}.jwt",
    show_default=True,
    required=True,
    help="The Output file (name) format (allows key based substitution for subject name).",
)
@click.option(
    "--private-key-file",
    type=str,
    default="keys/private_key.pem",
    show_default=True,
    required=True,
    help="The RSA Private Key file file path (must be in PEM format).",
)
def click_generate_gizmosql_token(issuer: str,
                                  audience: str,
                                  subject: str,
                                  role: str,
                                  token_lifetime_seconds: int,
                                  output_file_format: str,
                                  private_key_file: str,
                                  ):
    generate_gizmosql_token(**locals())
