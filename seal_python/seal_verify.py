import warnings
from .seal_meta import SealMetadata
from .seal_dns  import SealDNS
from typing import List
import dns.resolver as DNS, dns.rdatatype as DNS_TYPE

def verify_seal(s_meta: SealMetadata, digest_bytes: bytes):
    if s_meta.s is None:    raise ValueError("Missing signature")
    
    # Fetch byte range:
    digest       = s_meta.da_hash(digest_bytes)
    
    if (s_meta.sf.date_format is not None) or (s_meta.id is not None): # Double digest
        digest1 = digest.digest()
        head = ""
        if s_meta.id is not None:
            head = s_meta.id + ":" + head
        if s_meta.sf.date_format is not None:
            head = s_meta.s.date_str() + ":" + head
        digest2 = head.encode() + digest1
        digest = digest.new(digest2)
        

    # Retrieve the public key from the DNS entry
    seal_dns_arr = get_seal_dns(s_meta.d)
    if len(seal_dns_arr) == 0:
        raise ValueError("Unable to find a valid SEAL DNS entry")
    
    for seal_dns in seal_dns_arr:
        warn_pre = f"Invalid SEAL DNS record   (domain={s_meta.d})\n    {str(seal_dns)}\n    "

        if seal_dns.seal != s_meta.seal:     # TODO: Do you just reject all versions != 1?
            warnings.warn(warn_pre + f"DNS version ({seal_dns.seal}) != Record version ({s_meta.seal})");  continue
    
        if seal_dns.ka != s_meta.ka:  
            warnings.warn(warn_pre + f"DNS key algorithm ({seal_dns.ka}) != Record key algorithm ({s_meta.ka})");  continue
    
        if seal_dns.kv != s_meta.kv:  
            warnings.warn(warn_pre + f"DNS key version ({seal_dns.kv}) != Record key version ({s_meta.kv})");  continue

        if seal_dns.uid != s_meta.uid: 
            warnings.warn(warn_pre + f"DNS uid ({seal_dns.uid}) != Record uid ({s_meta.uid})");  continue
    
        if seal_dns.p is None: # Public key revoked  # TODO: Should this check for other DNS records? 
            raise ValueError(f"All instances of the public key (kv={s_meta.kv}) are revoked")
    
        if (seal_dns.r is not None and (s_meta.s.sig_d is None or seal_dns.r.time < s_meta.s.sig_d)):
            raise ValueError(f"All signatures after {seal_dns.r} are revoked")
        
        # Decrypt the signature using the public key
        try:
            result = s_meta.ka_verify(seal_dns.p, digest)
        except RuntimeError as e:
            warnings.warn(warn_pre + str(e));  continue
            
        if result: return
        else:
            warnings.warn(warn_pre + f"Calculated digest ({digest.digest().hex()}) != Expected digest");  continue

    raise ValueError("No matching DNS entry found")


# For testing, use signmydata.com
def get_seal_dns(domain: str) -> List[SealDNS]:
    try:
        result = DNS.resolve(domain, "TXT")
    except (DNS.NXDOMAIN, DNS.YXDOMAIN, DNS.NoNameservers) as e:
        raise ValueError(f"Invalid domain: \"{domain}\"  ({str(e)})")
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
            warnings.warn(f"Invalid SEAL DNS record   (domain={domain})\n    {val_str}\n    {e}")
            continue
        seal_dns_arr.append(seal_dns)
    return seal_dns_arr