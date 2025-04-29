from .seal_meta import SealSignData_, SealSignData_F
from .seal_file import  SealEntry, SealFile
from .seal_signer import SealDummySign, SealSigner
from .log import log, log_h

import re
from typing import List
from io import BufferedReader as File


PNG_BYTE_RANGE = "F~S,s~s+2,s+7~f"

def seal_sign_png(s_file: SealFile, s_data: SealSignData_, s_sign: SealSigner, new_path: str="") -> None:
    """Inserts a SEAL metadata entry into a PNG file

    Args:
        s_file (SealFile): The PNG file
        s_data (SealSignData_): Data to include in the SEAL entry
        s_sign (SealSigner): Signing method
        new_path (str): Location for the signed file (none = overwrite previous file)

    Raises:
        ValueError: If the file is invalid (i.e. not a PNG) or malformed
    """
    seal = SealSignData_F.fromData(s_data, byte_range=PNG_BYTE_RANGE)

    # Scan the file for prior signatures
    seal_read_png(s_file)
    if s_file.is_finalised:  raise ValueError("File is already finalised")
    if not s_file.load_pos("IEND"): raise ValueError("File improperly formatted (missing IEND chunk)")

    
    # Generate the dummy signature
    sig_size = s_sign.signature_size(seal)
    dummy_seal = s_file.sign_seal_data(seal, SealDummySign(sig_size))
    log(f"Signing: {dummy_seal} (dummy)")
    dummy_chunk = generate_seal_chunk(dummy_seal.toWrapper().encode())
    S_i = s_file.insert_seal_block(dummy_chunk, dummy_seal, 8, new_path)

    # Generate the real signature
    signed_seal = s_file.sign_seal_data(seal, s_sign)
    log(f"Signing: {signed_seal}")
    chunk_b = generate_seal_chunk(signed_seal.toWrapper().encode())
    s_file.insert_seal_block(chunk_b, signed_seal, 8, S_i=S_i)
    s_file.reset_pos()

def seal_read_png(s_file: SealFile) -> list[SealEntry]:
    """ Fetches SEAL metadata entries from a PNG file

    Parses the PNG file, extracting all SEAL metadata entries. 
    Each entry is validated by fetching the public key from the provided DNS entry.

    Args:
        s_file (SealFile): The PNG file

    Raises:
        Warning: If a SEAL entry is invalid or malformed (continues to parse)
        ValueError: If the file is invalid (i.e. not a PNG) or malformed

    Returns:
        SealFile: The updated SealFile containing all valid SEAL entries"""
    s_file.reset()
    cmp_str = b"\x89PNG\r\n\x1a\n"
    if s_file.read(len(cmp_str)) != cmp_str:  raise ValueError("Invalid PNG, missing PNG header")

    # Go through each PNG chunk
    # If SEAL, text or itxt, check for signature
    # If exif, check for special exif processing
    chunk_size_b = s_file.read(4)
    chunk_type_b = list(s_file.read(4))
    log("--type---bytes--")
    while len(chunk_type_b) > 0:
        chunk_size  = int.from_bytes(chunk_size_b, "big")
        chunk_type  = ''.join(map(chr, chunk_type_b))
        if(not(re.match("^[a-zA-Z]*$", chunk_type))): 
            raise ValueError(f"Invalid PNG, contains a chunk of type \"{chunk_type}\"")
        
        log(f"--{chunk_type}     {chunk_size}")

        if(chunk_type.lower() in ["text", "itxt", "seal"]):
            log_h("│   ")
            result = s_file.read_txt_block(chunk_size)
            
            if result[1] is not None:
                
                seal = result[1]
                [pt1, sig] = seal.toWrapper().split("s=")
                pt2 = sig.split(":")[0]+":..." if sig.count(':') > 0 else "..."
                seal_str = pt1+"s="+pt2+"/>"

                log_h()
                log("│ " + ('✓' if result[0] else '✕') + " " + seal_str)
            else: log_h()
        else:
            if chunk_type.lower() == "iend":  # For writing later
                s_file.save_pos("IEND", -8)
            s_file.read(chunk_size)
        
        s_file.read(4)

        # Next chunk
        chunk_size_b = s_file.read(4)
        chunk_type_b = list(s_file.read(4))

    log("-------PNG------")
    s_file.reset_pos()
    return s_file.seal_arr

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