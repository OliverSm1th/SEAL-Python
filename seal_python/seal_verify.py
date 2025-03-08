import warnings
from .seal_meta import Hash, SealVerifyData, SealBaseData
from .seal_dns  import SealDNS
from .log import log
from typing import List
import dns.resolver as DNS, dns.rdatatype as DNS_TYPE

def verify_seal_s(s_data: SealBaseData, digest: Hash, sig: str):
    s_data_ = SealVerifyData.fromData(s_data, sig=sig)
    return verify_seal(s_data_, digest)

def verify_seal(s_data: SealVerifyData, digest: Hash):
    if s_data.s is None:    raise RuntimeError("Missing signature")
    
    # Fetch byte range:
    # digest       = s_data.da_hash(digest_bytes)
    # log(f"Digest ({s_data.da}): {digest.hexdigest()}")
    
    if (s_data.sf.date_format is not None) or (s_data.id is not None): # Double digest
        digest1 = digest.digest()
        head = ""
        if s_data.id is not None:
            head = s_data.id + ":" + head
        if s_data.sf.date_format is not None:
            head = s_data.s.date_str() + ":" + head
        digest2 = head.encode() + digest1
        digest = digest.new(digest2)
        log(f"Double Digest: {digest.hexdigest()}")
        

    # Retrieve the public key from the DNS entry
    seal_dns_arr = get_seal_dns(s_data.d)
    if len(seal_dns_arr) == 0:
        raise ValueError("Unable to find a valid SEAL DNS entry")
    
    for seal_dns in seal_dns_arr:
        warn_pre = f"Invalid SEAL DNS record   (domain={s_data.d})\n    {str(seal_dns)}\n    "

        if seal_dns.seal != s_data.seal:     # TODO: Do you just reject all versions != 1?
            warnings.warn(warn_pre + f"DNS version ({seal_dns.seal}) != Record version ({s_data.seal})");  continue
    
        if seal_dns.ka != s_data.ka:  
            warnings.warn(warn_pre + f"DNS key algorithm ({seal_dns.ka}) != Record key algorithm ({s_data.ka})");  continue
    
        if seal_dns.kv != s_data.kv:  
            warnings.warn(warn_pre + f"DNS key version ({seal_dns.kv}) != Record key version ({s_data.kv})");  continue

        if seal_dns.uid != s_data.uid: 
            warnings.warn(warn_pre + f"DNS uid ({seal_dns.uid}) != Record uid ({s_data.uid})");  continue
    
        if seal_dns.p is None: # Public key revoked  # TODO: Should this check for other DNS records? 
            raise ValueError(f"All instances of the public key (kv={s_data.kv}) are revoked")
    
        if (seal_dns.r is not None and (s_data.s.date is None or seal_dns.r.time < s_data.s.date)):
            raise ValueError(f"All signatures after {seal_dns.r} are revoked")
        
        log(f"DNS Key: {str(seal_dns.p)[:130]}")
        
        # Decrypt the signature using the public key
        try:
            result = s_data.ka_verify(seal_dns.p, digest)
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