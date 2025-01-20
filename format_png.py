from seal_meta import SealMetadata, SealSignData
from seal_file import  SealFile
from seal_models import SealBase64
from seal_signer import SealDummySign, SealLocalSign, SealRemoteSign, SealSigner

import re
from typing import List
from io import BufferedReader as File



def seal_sign_png(s_file: SealFile, s_data: SealSignData, s_sign: SealSigner, new_path: str):
    seal = SealMetadata.fromData(s_data, byte_range="F~S,s~s+2,s+7~f")

    # Scan the file for prior signatures
    s_file = seal_read_png(s_file)
    if s_file.is_finalised:  raise ValueError("File is already finalised")
    if not s_file.load_pos("IEND"): raise ValueError("File improperly formatted (missing IEND chunk)")

    
    # Generate the dummy signature
    sig_size = s_sign.signature_size(seal)
    print(sig_size)
    dummy_seal = s_file.sign_seal_meta(seal, SealDummySign(sig_size))
    print("   "+str(dummy_seal))
    dummy_chunk = generate_seal_chunk(dummy_seal.toWrapper().encode())
    S_i = s_file.insert_seal_block(dummy_chunk, dummy_seal, 8, new_path)

    # Generate the real signature
    signed_seal = s_file.sign_seal_meta(seal, s_sign)
    print("   "+str(signed_seal))
    chunk_b = generate_seal_chunk(signed_seal.toWrapper().encode())
    s_file.insert_seal_block(chunk_b, signed_seal, 8, S_i=S_i)
    s_file.reset()

def seal_read_png(s_file: SealFile) -> SealFile:
    """Fetches SEAL metadata entries from a PNG file

    Parses the PNG file, extracting all SEAL metadata entries. 
    Each entry is validated by fetching the public key from the provided DNS entry.

    If a specific SEAL entry is found to be invalid or malformed, throws a Warning and continues

    :param str file_path: The PNG file
    :return SealFile: The updated SealFile containing all valid SEAL entries
    :raises Warning: If a SEAL entry is invalid or malformed (continues to parse)
    :raises ValueError: If the file is invalid (i.e. not a PNG) or malformed
    """
    cmp_str = b"\x89PNG\r\n\x1a\n"
    if s_file.read(len(cmp_str)) != cmp_str:  raise ValueError("Invalid PNG, missing PNG header")

    # Go through each PNG chunk
    # If SEAL, text or itxt, check for signature
    # If exif, check for special exif processing
    chunk_size_b = s_file.read(4)
    chunk_type_b = list(s_file.read(4))
    print("┌─type────bytes─┐")
    while len(chunk_type_b) > 0:
        chunk_size  = int.from_bytes(chunk_size_b, "big")
        chunk_type  = ''.join(map(chr, chunk_type_b))
        if(not(re.match("^[a-zA-Z]*$", chunk_type))): 
            raise ValueError(f"Invalid PNG, contains a chunk of type \"{chunk_type}\"")
        
        print(f"├─{chunk_type}     {chunk_size}")

        
        if(chunk_type.lower() in ["text", "itxt", "seal"]):  # TODO: for tEXt do you separate the keyword?
            result = s_file.read_txt_block(chunk_size)
            
            if result[1] is not None:
                seal = result[1]
                [pt1, sig] = seal.toWrapper().split("s=")
                pt2 = sig.split(":")[0]+":..." if sig.count(':') > 0 else "..."
                seal_str = pt1+"s="+pt2+"/>"

                print("│ " + ('✓' if result[0] else '✕') + " " + seal_str)
        else:
            if chunk_type.lower() == "iend":  # For writing later
                s_file.save_pos("IEND", -8)
            s_file.read(chunk_size)
        
        s_file.read(4)

        # Next chunk
        chunk_size_b = s_file.read(4)
        chunk_type_b = list(s_file.read(4))

    print("└──────PNG──────┘")
    s_file.reset()
    return s_file

# Helper Functions;
def compare_b_str(b: File, cmp_str: bytes) -> bool:
    return b.read(len(cmp_str)) == cmp_str

def is_png(file: File) -> bool:
    """Checks for the [PNG header](http://www.libpng.org/pub/png/spec/1.2/PNG-Rationale.html#R.PNG-file-signature)
    ::return:: True if the file starts with the PNG header"""
    return compare_b_str(file, b"\x89PNG\r\n\x1a\n")

def generate_seal_chunk(data_b: bytes) -> bytes:
    len_b = int.to_bytes(len(data_b), 4, byteorder="big")
    type_b = bytes(map(ord, "sEAl"))
    chunk_crc = crc(type_b + data_b)
    chunk_b = len_b + type_b + data_b + int.to_bytes(chunk_crc, 4, byteorder="big")
    return chunk_b


# CRC Implemention using: https://www.w3.org/TR/REC-png-961001#CRCAppendix

crc_table: List[int] = []
def populate_crc_table() -> None:
    for n in range(256):
        c = n
        for k in range(8):
            if ((c & 1) == 1):  # n is even
                c = 0xedb88320 ^ ((c >> 1)&0x7FFFFFFF)
            else:
                c = ((c >> 1)&0x7FFFFFFF)
        crc_table.append(c)

def crc(inp_b: bytes) -> int:
    if(len(crc_table) == 0): populate_crc_table()
    c = 0xffffffff

    for byte in inp_b:
        c = crc_table[(c ^ byte) & 0xff] ^ ((c >> 8)&0xFFFFFF)
    return c ^ 0xffffffff

# TEST_PNG = "../tests/valid4.png"
# with SealFile(TEST_PNG) as s_file:
#     seal_read_png(s_file)

useLocal = False

TEST_PNG = "./tests/seal.png"
num = "" if useLocal else "2"
SIGNED_PNG = f"./tests/seal-sign{num}.png"
with SealFile(TEST_PNG) as s_file:
    # seal_read_png(s_file)

    s_data = SealSignData(
        d="***REMOVED***" if useLocal else "signmydata.com",
        sf="base64",
        # id="***REMOVED***"
        id="***REMOVED***"
    )

    l_sign = SealLocalSign(
                      "MIIEogIBAAKCAQEAspKfzW955TEnslAoFqwl6kEZxRphmWC7JC5uUJNXjdR7ECX2\
                    rN3aC2WUf89yoE7Wwu8cOmH2QU4uWtA4BFGfETtRORRhsTyGjFRYBDM7uFZDIZ5O\
                    tIGqlqq+L6fqsojTpm5ZDnWFFSCWSYSSO1RCZ/iU+IOOoLCNoFJJHbjWrG+pP7Pv\
                    81qk7HOhOpXlKDYUD+ARVmXDPHzNrcaOXBk9NIdZV++SAQbm97bsKd2hf3G1BrES\
                    1D9TOxc1JW/e3e91XcD6FvUEhdhFMCLaSTMi4vAHABmCScyDUPzPMBqadiNvOnu8\
                    XPubWsWsO7o1vHdxwF7JcVgJATQJJ93Z7fmVtwIDAQABAoIBAAqzs4oPV+x+xqnu\
                    wzL1/DZkJ77ioYjHUvqMdyYIaTiMdxefqX9GCHmjC9mhEss9Y6zpFvWqG0+3TMXl\
                    MVuTkgc+rn56PzntA69IpWxoWaLm4JJqN2ilVhY+Lgm9yYNg+eDr6hXDa0dkiD09\
                    tGSD3JBN8Iz4QsWp7xhK9it8LA7HbzT0mpWbuYqDor8+9O5YfcE0FmIw2w3Bt6nj\
                    MKyyVrEYWFWppHsZzrU9utaw3tfhI3d9r3S9C2XT9L/0bT/wCr71HW4pJCvc4nT8\
                    q4Gvd1VIZTLST25dcX0HJ/bZUsb39+3hF4YVIJUN/6uD0fqP0mbBiwtUs4moE6Oh\
                    VNW8AaECgYEA8taA+dLD2+1vtU+lW7GJ+5wD2LM1/7UBACTvNmrdUpoeLkXJil79\
                    ChOMOZz7tn6m7afuedcHEb6SVBisDORGBAQUV4k3qau2syhde1/JUQxg3B8BpW7E\
                    Uv3Ui57cB75FtqohhSeJVcfkCFD13/nd0JWyCF8Fuk0yA3RlHizFy+cCgYEAvEBo\
                    2chRJJQLrrkCpSUQErF8b3/uWhhvIX0YyioXN5219tGfiQHw4+JKoTqUsJ6MHpp0\
                    MO+3hOOyDb8ammXGNQnRXtY5ehKHW89iF92YmFLOtQAbWBucSMIBgT9tLbGrQfLb\
                    kapVnXHGt73Ij6hH627EtaFL7bGqNRVUEpygLbECgYBHF0j22h8AmYgkekaci2Mr\
                    x8bQf9aFH4ZFdoqZUbutXPUM8t1HpvtJIePhUfXWvUk9NfZ4sNye8z1/ZSGpPILK\
                    1i7mWYN0JpL77AtB/Q7ArXEFwAYJWl4bNbgtj7o2ghuCmFfr1WE9PaGiVaFFiq7H\
                    S6utC7Rvj/3eSQr5RH47bQKBgHUZI5+EiWTVakbu8oRDf7IBEURSMbN9S3NrW0Y1\
                    1GdWBOBZGIGi4XL/SijsRZ1vof1PWkMueduBvznpy+SKtjY7uy7g1rPmXqhvYbcy\
                    sj7eE5JnVJsD4b0oYMNC7ujjgYHuTUJY0BS1t0SIGv+xT7tVFatdf9uFDjki4T8K\
                    imChAoGAP4ha1dLRtKk8p70/GfvM2c3WMD4UitbXG80h8dXiyaxB5sgeFVF2HprM\
                    H+9/qjDdTUOl1V+YEkWp3PAh3UUHODo0z7qKz/gia5gPTC3TJI0PGqRKKYpFJthF\
                    B4gDzF7IeUngPAIx65A1M6b+9mO+WkG/tepdJqmDmvj5ZEXf03o=")
    r_sign = SealRemoteSign(
        "https://signmydata.com/?sign",
        # "http://localhost:8080",
        "***REMOVED***"
    )

    seal_sign_png(s_file, 
                  s_data,
                  l_sign if useLocal else r_sign,
                  "./tests/seal-sign.png"
                  )
    seal_read_png(s_file)

