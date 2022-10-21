#!/usr/bin/env python
# -*- coding: utf-8 -*-
from typing import cast

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from os.path import exists

from sigstore_shim import sigstore_shim

# Fetch keypair from disk, or create one if not found
def get_keypair():
    if not exists("private.key"):
        print("Private key not found, creating a new one...")
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend()).private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open("private.key", 'wb') as pem_out:
            pem_out.write(private_key)

    with open("private.key", 'rb') as pem_in:
        pemlines = pem_in.read()
    private_key = load_pem_private_key(pemlines, None, default_backend())
    public_key = private_key.public_key()

    # Write public key to a file
    with open("public.pem", "wb") as pem_out:
        pem_out.write(public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))


def main():
    print(" --- SIGNING STEP --- ")

    artifact = b"Sigstore is the future!"

    # Sign artifact using sigstore staging infrastructure
    signing_result = sigstore_shim.sign(artifact)

    print("Using ephemeral certificate:")
    print(signing_result.cert_pem)

    print(f"Transparency log entry created at index: {signing_result.log_entry.log_index}")

    artifact_signature = signing_result.b64_signature
    artifact_certificate = signing_result.cert_pem.encode()

    print(" --- VERIFICATION STEP --- ")

    sigstore_shim.verify(artifact, artifact_certificate, artifact_signature)


if __name__ == "__main__":
    main()
