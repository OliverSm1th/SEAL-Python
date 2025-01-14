from seal_meta import SealMetadata
from seal_models import SealBase64


def sign_seal_local(seal_meta: SealMetadata, private_key: SealBase64, digest_bytes: bytes) -> SealMetadata:
    digest = seal_meta.da_hash(digest_bytes)

    signature = seal_meta.ka_encrypt(private_key, digest)
    seal_meta.set_signature(signature)

    return seal_meta