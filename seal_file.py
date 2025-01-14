from io import BufferedReader as File
import re
from typing import List, Tuple, Optional as Opt, NamedTuple, Dict
import warnings
from seal_models import BytePos, SealBase64, SealByteRange
from seal_meta import SealMetadata
from seal_sign import sign_seal_local
from seal_verify import verify_seal

# Stores the positions and metadata for the SEAL entries

class SealEntry(NamedTuple):
    start: int
    end:   int
    seal:  SealMetadata

class SealFile():
    r_file:         File
    r_file_path:    str
    seal_arr:       List[SealEntry] = []
    saved_pos:      Dict[str, int]  = {}
    is_finalised:   bool            = False
    
    def __init__(self, file: str):
        self.r_file_path = file
        self.r_file = open(file, "rb")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
    
    def close(self):
        self.r_file.close()

    
    def read(self, b_len: int) -> bytes:
        return self.r_file.read(b_len)

    def read_txt_block(self, block_len: int) -> Tuple[bool, Opt[SealMetadata]]:
        block_start = self.r_file.tell()

        block_bytes = self.r_file.read(block_len)
        block_str   = str.strip(block_bytes.decode())        

        if not re.match("^<((\\*:)|\\?)?seal ", block_str):   return (False, None)
        
        try:
            seal = SealMetadata.fromWrapper(block_str)    # Throws ValueError if improperly structured
        except ValueError as e:  
            warnings.warn(f"  Invalid SEAL structure- {str(e)}")
            return (False, None)
    
        # Get signature start + end pos (S+s)
        S = block_str.index(" s=") + 3
        s = len(block_str) - 3
        #   Escape quotation marks  ' "
        if block_str[S] == block_str[s] and block_str[S] in ['\'', '\"']:  
            S += 1; s -= 1

        self.seal_arr.append(SealEntry(block_start + S, block_start + s + 1,seal))

        try:
            self.verify_seal(seal)              # Throws ValueError if invalid
        except ValueError as e:
            warnings.warn(f"  Invalid SEAL- {str(e)}")
            self.seal_arr.pop()  # Remove invalid SEAL recordseal_num-1
            return (False, seal)  
        return (True, seal)
    
    def verify_seal(self, seal: SealMetadata):
        if self.is_finalised:
            raise ValueError(f"File is already finalised, cannot include any extra signatures")
        # Assumes SEAL records are ordered in increasing byte ranges:
        if len(self.seal_arr) == 0:
            if not(seal.b.includes_lit('F')):
                warnings.warn(f"Digest byte range starts at: \'{seal.b.str_start()}\', should be \'F\' for full coverage")
        else:
            if not(seal.b.includes_lit('F') or seal.b.includes_lit('P')):
                warnings.warn(f"Digest byte range starts at: \'{seal.b.str_start()}\', should be \'F\' or \'P\' for full coverage")

        # Fetch byte range:
        digest_bytes = self.fetch_byte_range(seal.b)

        # Verify:
        verify_seal(seal, digest_bytes)         # Throws ValueError if invalid  
    
    def sign_seal_meta(self, seal: SealMetadata, priv_key: SealBase64) -> SealMetadata:
        # Fetch byte range:
        digest_bytes = self.fetch_byte_range(seal.b)

        return sign_seal_local(seal, priv_key, digest_bytes)

    
    def insert(self, bytes: bytes, new_path: str):
        """Create a new file with the given bytes inserted at the current position

        Raises OSError if unable to open the new file
        Raises BlockingIOError if unable to write to the file
        """
        # https://stackoverflow.com/questions/18838919/append-to-a-file-after-nth-byte-in-python
        cur_pos = self.r_file.tell()
        self.r_file.seek(0,0)   # Move to start
        w_file = open(new_path, 'wb')
        w_file.write(self.r_file.read(cur_pos))  # Copy file up to the current point
        w_file.write(bytes)
        # print(''.join(map(chr, list(self.r_file.read(4)))))
        

        w_file.write(self.r_file.read(4))
        w_file.close()

    def save_pos(self, key: str, offset: int = 0) -> None:
        self.saved_pos[key] = self.r_file.tell() + offset
    
    def load_pos(self, key: str) -> bool:
        if not key in self.saved_pos: return False
        self.r_file.seek(self.saved_pos[key], 0)
        return True

    def fetch_byte_range(self, br: SealByteRange, S_i: int = 0) -> bytes:
        prev_pos = self.r_file.tell()
        digest_bytes : bytes = b''

        for (start, end) in br.byte_range:
            start_pos = self._file_pos(start, S_i)
            end_pos   = self._file_pos(end,   S_i)
            # print(f"{start_pos} -> {end_pos}")
            self.r_file.seek(start_pos, 0 if start_pos>=0 else 2) # 0 = From Start, 2 = From End
            if end_pos >= 0:    # Read up to the required position
                result = self.r_file.read(end_pos-start_pos)
            else:               # Read the rest of the file + remove the required offset
                result = self.r_file.read(-1)
                result[:end_pos+1]
            digest_bytes += result
        self.r_file.seek(prev_pos, 0)
        
        return digest_bytes
    
    def _file_pos(self, bp: BytePos, S_i: int) -> int:
        seal_num = len(self.seal_arr)

        if bp.literal in 'Ss' and (S_i >= seal_num or seal_num==0):
            raise RuntimeError(f"Invalid byte pos: {bp.literal} for SEAL block #{S_i}, block not added yet (size={seal_num})")
        if bp.literal in 'Pp' and S_i == 0:
            raise RuntimeError(f"Invalid byte pos: {bp.literal} for SEAL block #{S_i}, no previous signature yet")

        match bp.literal:
            case 'F':
                cur_pos = 0
            case 'f':
                cur_pos = -1
            case 'S':
                cur_pos = self.seal_arr[S_i].start
            case 's':
                cur_pos = self.seal_arr[S_i].end
            case 'P':
                cur_pos = self.seal_arr[S_i-1].start
            case 'p':
                cur_pos = self.seal_arr[S_i-1].end

        return cur_pos + bp.offset


    # ---Not Used/Broken--
    def _last_seal(self) -> Opt[SealMetadata]:
        i = len(self.seal_arr)-1
        if len(self.seal_arr) > 0:
            return self.seal_arr[-1].seal
        return None

    # (allowing for multiple SEAL signatures per block)
    """
    def read_seal_block(self, block_len: int):
        \"""Parses and validates a SEAL block with the structure <seal .../> ... <seal .../>

        :param block_len: Length of block
        :type block_len: int
        :raises Warning: Prints a warning if it finds an invalid or malformed SEAL entry
        :raises ValueError: An error is thrown if the block is not a valid SEAL block
        \"""         
        block = self.file.read(block_len)
        S = self.file.tell()
        s = S + block_len
        self.seal_pos.append((S, s))

        block_str = str.strip(block.decode())

        seal_block : List[SealMetadata] = []
        seal_i = self.seal_arr_i[-1] if len(self.seal_arr_i)>0 else -1
        if not re.match("^<((\\*:)|\\?)?seal ", block_str):
            raise ValueError("Invalid SEAL block")

        while re.match("^<((\\*:)|\\?)?seal ", block_str):
            seal_i += 1

            if not ("/>" in block_str):
                warnings.warn("SEAL #{seal_i}: Invalid record, should be of the form <seal .../>")
                warnings.warn("Invalid SEAL record: \'Expecting a \"/>\" to terminate (#{seal_i})\'")
                self.seal_arr.append(seal_block)
                return
            
            block_str = block_str[block_str.index("seal")+5:]
            end_i     = block_str.index("/>")
            seal_str  = block_str[:end_i]
            block_str = block_str[end_i+2:]

            print(f"SEAL #{seal_i}")
            print(seal_str)
            
            if self.is_finalised:
                warnings.warn("     Invalid record, cannot include another signature after a finalized signature")
                continue            

            try:
                seal = SealMetadata.fromWrapper(seal_str)
            except ValueError as e:
                warnings.warn(f"     Invalid record:  \'{str(e)}\', skipping")
                continue
            except Warning as w:
                warnings.warn(f"    {w}")

            if len(self.seal_arr) > 0 and seal.b.overlaps(self.seal_arr[-1]):
                warnings.warn(f"    Invalid record: Overlaps with previous signature")
                continue

            
            if seal.b.includes_lit("f", True): # Finalised
                self.is_finalised = True
            
            seal_block.append(seal)

        self.seal_arr.append(seal_block)
    """

    def end_verify(self):
        last_block = self.seal_arr[-1]
        last_seal  = last_block[-1]
        seal_i = len(self.seal_arr) - 1

        if not(last_seal.b.includes_lit('f')):
            warnings.warn(f"SEAL record #{seal_i}: Digest byte range ends at: \'{last_seal.b.str_end()}\', should be \'f\' for full coverage")

