from datetime import datetime
from seal_meta import SealMetadata
from seal_models import SealBase64
from seal_signer import SealSigner


def sign_seal(s_meta: SealMetadata, signer: SealSigner, digest_bytes: bytes) -> SealMetadata:
    date = None

    digest = s_meta.da_hash(digest_bytes)

    if (s_meta.sf.date_format is not None) or (s_meta.id is not None):
        # Double digest
        digest1 = digest.digest()
        head = ""
        if s_meta.id is not None:
            head = s_meta.id + ":" + head
        if s_meta.sf.date_format is not None:
            date = datetime.now()
            head = s_meta.sf.format_date(date) + ":" + head
        digest2 = head.encode() + digest1
        digest = digest.new(digest2)

    signature = signer._generate_signature(s_meta, digest.digest())
    s_meta.set_signature(signature, date)

    return s_meta
