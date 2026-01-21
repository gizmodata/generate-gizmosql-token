import datetime
import json
import uuid
from typing import Optional, List, Dict

import click
import jwt


def generate_gizmosql_token(issuer: str,
                            output_file_format: str,
                            private_key_file: str,
                            audience: str,
                            subject: str,
                            role: str,
                            token_lifetime_seconds: int,
                            catalog_access: Optional[List[Dict[str, str]]] = None,
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

        # Add catalog_access if provided
        if catalog_access:
            payload["catalog_access"] = catalog_access

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
@click.option(
    "--catalog-access",
    type=str,
    default=None,
    help='JSON array of catalog access rules. Example: '
         '\'[{"catalog":"accounting","access":"write"},{"catalog":"*","access":"read"}]\'. '
         'Each rule must have "catalog" and "access" fields. '
         'Use "*" as wildcard for catalog. Valid access values: "write", "read", "none".',
)
def click_generate_gizmosql_token(issuer: str,
                                  audience: str,
                                  subject: str,
                                  role: str,
                                  token_lifetime_seconds: int,
                                  output_file_format: str,
                                  private_key_file: str,
                                  catalog_access: Optional[str],
                                  ):
    # Parse catalog_access JSON if provided
    parsed_catalog_access = None
    if catalog_access:
        try:
            parsed_catalog_access = json.loads(catalog_access)
            # Validate structure
            if not isinstance(parsed_catalog_access, list):
                raise click.BadParameter("catalog_access must be a JSON array")
            for rule in parsed_catalog_access:
                if not isinstance(rule, dict):
                    raise click.BadParameter("Each catalog_access rule must be an object")
                if "catalog" not in rule or "access" not in rule:
                    raise click.BadParameter("Each rule must have 'catalog' and 'access' fields")
                if rule["access"] not in ("write", "read", "none"):
                    raise click.BadParameter(f"Invalid access value: {rule['access']}. Must be 'write', 'read', or 'none'")
        except json.JSONDecodeError as e:
            raise click.BadParameter(f"Invalid JSON for catalog_access: {e}")

    generate_gizmosql_token(
        issuer=issuer,
        output_file_format=output_file_format,
        private_key_file=private_key_file,
        audience=audience,
        subject=subject,
        role=role,
        token_lifetime_seconds=token_lifetime_seconds,
        catalog_access=parsed_catalog_access,
    )
