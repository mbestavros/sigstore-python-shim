import base64
import hashlib
import requests
import simplejson as json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from textwrap import dedent
from typing import cast


from sigstore._internal.oidc.ambient import (
    detect_credential,
    GitHubOidcPermissionCredentialError
)
from sigstore._internal.oidc.issuer import Issuer
from sigstore._internal.oidc.oauth import (
    DEFAULT_OAUTH_ISSUER,
    STAGING_OAUTH_ISSUER,
    get_identity_token,
)
from sigstore._sign import Signer
from sigstore._verify import (
    CertificateVerificationFailure,
    VerificationFailure,
    Verifier,
)

REKOR_URL = "https://rekor.sigstore.dev"

REKOR_API_HEADERS = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
}

# Sign an artifact using sigstore-python. Returns SigningResult
def sign(artifact, identity_token=None, disable_oidc_ambient_providers=False, oidc_issuer=DEFAULT_OAUTH_ISSUER, staging=False):
    if staging:
        signer = Signer.staging()
    else:
        signer = Signer.production()

    if not identity_token and not disable_oidc_ambient_providers:
        try:
            identity_token = detect_credential()
        except GitHubOidcPermissionCredentialError as exception:
            # Provide some common reasons for why we hit permission errors in
            # GitHub Actions.
            print(
                dedent(
                    f"""
                    Insufficient permissions for GitHub Actions workflow.

                    The most common reason for this is incorrect
                    configuration of the top-level `permissions` setting of the
                    workflow YAML file. It should be configured like so:

                        permissions:
                          id-token: write

                    Relevant documentation here:

                        https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect#adding-permissions-settings

                    Another possible reason is that the workflow run has been
                    triggered by a PR from a forked repository. PRs from forked
                    repositories typically cannot be granted write access.

                    Relevant documentation here:

                        https://docs.github.com/en/actions/security-guides/automatic-token-authentication#modifying-the-permissions-for-the-github_token

                    Additional context:

                    {exception}
                    """
                )
            )
            raise exception
    if not identity_token:
        issuer = Issuer(oidc_issuer)
        identity_token = get_identity_token(
            "sigstore",
            "", # oidc client secret
            issuer,
        )

    return signer.sign(
        input_=artifact,
        identity_token=identity_token
    )


# Verify an artifact, signature, and certificate using sigstore-python. Returns boolean
def verify(artifact, crt, sig, staging=False):
    if staging:
        verifier = Verifier.staging()
    else:
        verifier = Verifier.production()

    result = verifier.verify(
        input_=artifact,
        certificate=crt,
        signature=sig
    )

    if result:
        print("Sigstore verification: OK")
        return True
    else:
        result = cast(VerificationFailure, result)
        print("Sigstore verification: FAIL")
        print(f"Failure reason: {result.reason}")
        return False


# Sign an artifact locally, then upload the signature, pubkey, and hash to Sigstore.
def sign_offline_and_upload(private_key, artifact):
    public_key = private_key.public_key()

    # Sign artifact
    artifact_signature = private_key.sign(
        artifact,
        ec.ECDSA(hashes.SHA256())
    )

    # Test signature
    try:
        public_key.verify(artifact_signature, artifact, ec.ECDSA(hashes.SHA256()))
        print('Artifact signature local verification passed.')
    except:
        print('Artifact signature local verification failed!')

    # Prepare inputs
    artifact_signature_b64 = base64.b64encode(artifact_signature)
    artifact_hash = hashlib.sha256(artifact).hexdigest()
    pub_b64 = _encode_pubkey(public_key)

    # Prepare upload payload
    payload_json = {
        "kind": "hashedrekord",
        "apiVersion": "0.0.1",
        "spec": {
            "signature": {
                "content": artifact_signature_b64,
                "publicKey": {
                    "content": pub_b64
                }
            },
            "data": {
                "hash": {
                    "algorithm": "sha256",
                    "value": artifact_hash
                }
            }
        }
    }
    payload = json.dumps(payload_json)

    return {
        "signature": artifact_signature,
        "response": requests.post(f"{REKOR_URL}/api/v1/log/entries", data=payload,  headers=REKOR_API_HEADERS),
    }

def search(email=None, pubkey=None, hash=None):
    if pubkey is not None:
        pubkey = _encode_pubkey(pubkey)
        pubkey = {
            "format": "x509",
            "content": pubkey,
        }
    if hash is not None:
        hash = f"sha256:{hash}"
    rekor_payload_search = {
        "email": email,
        "publicKey": pubkey,
        "hash": hash,
    }
    payload = json.dumps(rekor_payload_search)

    return requests.post(f"{REKOR_URL}/api/v1/index/retrieve", data=payload,  headers=REKOR_API_HEADERS)

def fetch_with_uuid(uuid):
    return requests.get(f"{REKOR_URL}/api/v1/log/entries/{uuid}",  headers=REKOR_API_HEADERS)

def fetch_with_inputs(signature, pubkey, hash):
    artifact_signature_b64 = base64.b64encode(signature)
    pub_b64 = _encode_pubkey(pubkey)

    rekor_payload_search = {
        "entries": [
            {
                "kind": "hashedrekord",
                "apiVersion": "0.0.1",
                "spec": {
                    "signature": {
                        "content": artifact_signature_b64,
                        "publicKey": {
                            "content": pub_b64
                        }
                    },
                    "data": {
                        "hash": {
                            "algorithm": "sha256",
                            "value": hash
                        }
                    }
                }
            }
        ],
    }
    payload = json.dumps(rekor_payload_search)

    return requests.post(f"{REKOR_URL}/api/v1/log/entries/retrieve", data=payload,  headers=REKOR_API_HEADERS)

def _encode_pubkey(pubkey):
    # serializing into PEM
    rsa_pem = pubkey.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    pub_pem = rsa_pem.decode("utf-8").replace("\\n", "")
    pbytes: bytes = bytes(pub_pem, encoding="raw_unicode_escape")
    return base64.b64encode(pbytes).decode("utf8")
