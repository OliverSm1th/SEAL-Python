import warnings
from seal_models import SealDNS, SealMetadata
from typing import List, Optional as Opt
import dns.resolver as DNS, dns.rdatatype as DNS_TYPE

# For testing, use signmydata.com
def get_seal_dns(domain: str) -> List[SealDNS]:
    try:
        result = DNS.resolve(domain, "TXT")
    except (DNS.NXDOMAIN, DNS.YXDOMAIN, DNS.NoNameservers) as e:
        raise ValueError(f"Invalid domain: \"{domain}\"")
    except DNS.NoAnswer:
        raise ValueError(f"Domain: \"{domain}\" has no TXT record")
    except DNS.LifetimeTimeout:
        raise ValueError(f"Unable to get domain info (timeout)")
    
    seal_dns_arr : List[SealDNS] = []

    for val in result:
        if val.rdtype != DNS_TYPE.TXT: continue
        try:
            val_str = val.to_text()
        except ValueError as e:
            warnings.warn(f"Unable to read DNS TXT record: {e}  (domain={domain})")
            continue
        val_str = "".join(val_str.split("\" \""))
        val_str = val_str.strip("\"")
        if not val_str.startswith("seal"): continue
        try:
            seal_dns = SealDNS.fromEntry(val_str)
        except ValueError as e:
            warnings.warn(f"Invalid SEAL DNS record: {e}\nDNS Record:   (domain={domain})\n   {val_str}")
            continue
        seal_dns_arr.append(seal_dns)
    return seal_dns_arr


def verify_seal(seal_meta: SealMetadata, digest_bytes: bytes):
    # Generate a digest of the file # file: SealFile
    # digest_bytes = file.fetch_byte_range(seal_meta.b)
    digest       = seal_meta.da_hash(digest_bytes)
    
    # Retrieve the public key from the DNS entry
    seal_dns_arr = get_seal_dns(seal_meta.d)
    if len(seal_dns_arr) == 0:
        raise ValueError("Unable to find a valid SEAL DNS entry")
    
    valid_dns_arr : List[SealDNS] = []
    for seal_dns in seal_dns_arr:
        if seal_dns.seal!= seal_meta.seal:continue # TODO: Do you just reject all versions != 1?
        if seal_dns.ka  != seal_meta.ka:  continue
        if seal_dns.kv  != seal_meta.kv:  continue
        if seal_dns.uid != seal_meta.uid: continue
        if seal_dns.p is None: # Public key revoked  # TODO: Should this check for other DNS records? 
            raise ValueError("All instances of the public key are revoked")
        if (seal_dns.r is not None and 
            (seal_meta.s.sig_d is None or seal_dns.r.time < seal_meta.s.sig_d)):
            raise ValueError(f"All signatures after {seal_dns.r} are revoked")
        valid_dns_arr.append(seal_dns)
    if len(valid_dns_arr) == 0:
        raise ValueError("No valid DNS entry found")
    
    for valid_dns in valid_dns_arr:
        if valid_dns.p is None: return
        # Decrypt the signature using the public key
        expected_digest = seal_meta.ka_decrypt(valid_dns.p)
        if digest == expected_digest: return
    
    raise ValueError("No matching DNS entry found")

# seal_dns_arr = get_seal_dns("signmydata.com")
# print("---RESULT---")
# for seal_dns in seal_dns_arr:
#     print(seal_dns)