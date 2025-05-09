"""
    SEAL: implemented in Python
    An open solution for assigning attribution with authentication to media.
    
    :copyright: Oliver Smith + Dr. Neal Krawetz, see LICENSE
    :license: MIT, see LICENSE for details
"""
__version__ = "0.0.1"
import sys
assert sys.version_info >= (3, 9)

from .seal_dns import SealDNS
from .seal_meta import SealMetadata, SealSignData, SealSignData_, SealBaseData, SealVerifyData, SealBase64
from .seal_file import SealFile, SealEntry
from .seal_signer import SealLocalSign, SealRemoteSign, SealSigner
# Verifying digest bytes:
from .seal_verify import verify_seal
# File Formats:
from .format_png import seal_sign_png, seal_read_png
# General Models: (mainly for testing) 
from .seal_models import SealByteRange, SealSignatureFormat, SealSignature, SealKeyVersion, SealUID, SealBase64, SealTimestamp, SealDigestInfo, Hash, SealBinaryFormat
