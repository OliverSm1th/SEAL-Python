import re
from seal_meta import SealMetadata
from seal_file import SealFile
from io import BufferedReader as File

"""
Functions for handling PNG files


"""

def compare_b_str(b: File, cmp_str: bytes):
    return b.read(len(cmp_str)) == cmp_str

def is_png(file: File) -> bool:
    # Checking for the PNG file signature  
    # http://www.libpng.org/pub/png/spec/1.2/PNG-Rationale.html#R.PNG-file-signature
    return compare_b_str(file, b"\x89PNG\r\n\x1a\n")

def seal_sign_png(file: File, seal: SealMetadata):
    # Scan the file for prior signatures
    s_file : SealFile = seal_read_png(file)
    if s_file.is_finalised:  raise ValueError("Cannot add SEAL info- file is already finalised")
    

    return


def seal_read_png(file: File) -> SealFile:
    """Fetches SEAL metadata entries from a PNG file

    Parses the PNG file, extracting all SEAL metadata entries. 
    Each entry is validated by fetching the public key from the provided DNS entry.

    If a specific SEAL entry is found to be invalid or malformed, throws a Warning and continues

    :param File file: The PNG file
    :return List[SealMetadata]: All valid SEAL metadata entries contained within the PNG File
    :raises Warning: Prints an warning if a SEAL entry is invalid or malformed (continues to parse)
    :raises ValueError: An error thrown if the file is invalid (not a PNG) or malformed
    """
    if not is_png(file): raise ValueError("Invalid PNG, missing PNG header")

    s_file = SealFile(file)

    # Go through each PNG chunk
    # If SEAL, text or itxt, check for signature
    # If exif, check for special exif processing
    chunk_size_b = s_file.read(4)
    chunk_type_b = list(s_file.read(4))
    while len(chunk_type_b) > 0:
        chunk_size  = int.from_bytes(chunk_size_b, "big")
        chunk_type  = ''.join(map(chr, chunk_type_b))
        if(not(re.match("^[a-zA-Z]*$", chunk_type))): 
            raise ValueError(f"Invalid PNG, contains a chunk of type \"{chunk_type}\"")
        print(f"Chunk: size={chunk_size}   type={chunk_type}")
        
        if(chunk_type.lower() in ["text", "itxt", "seal"]):  # TODO: for tEXt do you separate the keyword?
            result = s_file.read_txt_block(chunk_size)
            if result:
                print("Found valid SEAL entry")
        else:
            s_file.read(chunk_size)
        
        s_file.read(4)

        # Next chunk
        chunk_size_b = s_file.read(4)
        chunk_type_b = list(s_file.read(4))
    file.seek(0, 0)
    return s_file


TEST_PNG = "./tests/files/png/test-badsig-Pp.png"
file = open(TEST_PNG, "rb")
seal_read_png(file)


file.close()
