from datetime import datetime
from seal_meta import SealMetadata
from seal_models import SealBase64, SealSignature


def sign_seal_local(s_meta: SealMetadata, private_key: SealBase64, digest_bytes: bytes) -> SealMetadata:
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

    signature = s_meta.ka_encrypt(private_key, digest)
    s_meta.set_signature(signature, date)

    return s_meta