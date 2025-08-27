# generate-gizmosql-token
A utility repo for generating Bearer Authentication Tokens (Javascript Web Tokens - JWTs) for testing [GizmoSQL](https://github.com/gizmodata/gizmosql) token authentication.

# Setup (to run locally)

## Install Python package
### from source - for development
```shell
git clone https://github.com/gizmodata/generate-gizmosql-token

cd generate-gizmosql-token

# Create the virtual environment
python3 -m venv .venv

# Activate the virtual environment
. .venv/bin/activate

# Upgrade pip, setuptools, and wheel
pip install --upgrade pip setuptools wheel

# Install the package (in editable mode)
pip install --editable .[dev]
```

### Note
For the following commands - if you are running from source and using `--editable` mode (for development purposes) - you will need to set the PYTHONPATH environment variable as follows:
```shell
export PYTHONPATH=$(pwd)/src
```

### Usage Example
```shell
generate-gizmosql-token \
  --issuer "GizmoData LLC" \
  --audience "GizmoSQL Server" \
  --subject "philip@gizmodata.com" \
  --role "admin" \
  --token-lifetime-seconds 86400 \
  --output-file-format "output/gizmosql_token_{issuer}_{audience}_{subject}.jwt" \
  --private-key-file keys/private_key.pem
```

### Handy development commands

#### Version management

##### Bump the version of the application - (you must have installed from source with the [dev] extras)
```bash
bumpver update --patch
```
