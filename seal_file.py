from io import BufferedReader as File
import re
from typing import Dict, List, Tuple, Optional as Opt, Union
import warnings
from seal_models import BytePos, SealByteRange, SealMetadata
from seal_verify import verify_seal

# Stores the positions and metadata for the SEAL entries

class SealFile():
    file:        File

    
    seal_pos:  List[Tuple[int, int]] = []


    def __init__(self, file: File):
        self.file = file
    
    def read(self, b_len: int) -> bytes:
        return self.file.read(b_len)

    def _file_pos(self, bp: BytePos, S_i: int) -> int:
        if bp.literal in 'Ss' and S_i >= len(self.seal_pos):
            raise RuntimeError(f"Invalid byte pos: {bp.literal} for SEAL block {S_i}, block not added yet ({S_i}/{len(self.seal_pos)-1})")
        if bp.literal in 'Pp' and S_i == 0:
            raise RuntimeError(f"Invalid byte pos: {bp.literal} for SEAL block {S_i}, no previous signature yet")

        match bp.literal:
            case 'F':
                cur_pos = 0
            case 'f':
                cur_pos = -1
            case 'S':
                cur_pos = self.seal_pos[S_i][0]
            case 's':
                cur_pos = self.seal_pos[S_i][1]
            case 'P':
                cur_pos = self.seal_pos[S_i-1][0]
            case 'p':
                cur_pos = self.seal_pos[S_i-1][1]

        return cur_pos + bp.offset
    
    def fetch_byte_range(self, br: SealByteRange, S_i: int = -1) -> bytes:
        prev_pos = self.file.tell()
        digest_bytes : bytes = b''

        for (start, end) in br.byte_range:
            start_pos = self._file_pos(start, S_i)
            end_pos   = self._file_pos(end,   S_i)
            self.file.seek(start_pos, 0 if start_pos>=0 else 2) # 0 = From Start, 2 = From End
            if end_pos >= 0:    # Read up to the required position
                digest_bytes += self.file.read(end_pos-start_pos)
            else:               # Read the rest of the file + remove the required offset
                result = self.file.read(-1)
                result[:end_pos+1]
        self.file.seek(prev_pos, 0)
        return digest_bytes


    def _read_seal_str(self, seal_str: str) -> SealMetadata:
        seal = SealMetadata.fromEntry(seal_str)  # Throws ValueError if invalid 

        #  Assumes SEAL records are ordered in increasing byte ranges:
        if len(self.seal_pos) == 0:
            if not(seal.b.includes_lit('F')):
                warnings.warn(f"Digest byte range starts at: \'{seal.b.str_start()}\', should be \'F\' for full coverage")
        else:
            if not(seal.b.includes_lit('F') or seal.b.includes_lit('P')):
                warnings.warn(f"Digest byte range starts at: \'{seal.b.str_start()}\', should be \'F\' or \'P\' for full coverage")
        
        print(seal)

        # Fetch byte range:
        digest_bytes = self.fetch_byte_range(seal.b)

        # Verify:
        verify_seal(seal, digest_bytes)         # Throws ValueError if invalid
        
        return seal


    def read_seal_block(self, block_len: int) -> Opt[List[SealMetadata]]:
        # Records the position of the signature
        block = self.file.read(block_len)
        S = self.file.tell()
        s = S + block_len
        self.seal_pos.append((S, s))

        block_str = str.strip(block.decode())

        seal_arr : List[SealMetadata] = []
        seal_i   = 0

        while re.match("^<((\\*:)|\\?)?seal ", block_str):
            if not ("/>" in block_str):
                warnings.warn("SEAL #{seal_i}: Invalid record, should be of the form <seal .../>")
                warnings.warn("Invalid SEAL record: \'Expecting a \"/>\" to terminate (#{seal_i})\'")
                return seal_arr
            block_str = block_str[block_str.index("seal")+5:]
            end_i     = block_str.index("/>")
            seal_str  = block_str[:end_i]
            block_str = block_str[end_i+2:]

            print(f"SEAL #{seal_i}")
            print(seal_str)
            try:
                seal = self._read_seal_str(seal_str)
            except ValueError as e:
                warnings.warn(f"    Invalid record:  \'{str(e)}\', skipping")
                continue
            except Warning as w:
                warnings.warn(f"   {w}")
            
            seal_arr.append(seal)
            seal_i += 1

        return seal_arr

    def read_txt_block(self, block_len: int) -> List[SealMetadata]:
        print("Reading TXT block")
        seal_arr = self.read_seal_block(block_len)

        if seal_arr is None:  # Not a SEAL block, remove position from seal_pos
            self.seal_pos.pop()
            return []
        return seal_arr

            

    def end_verify(self):
        last_seal = self.seal_list[-1]
        seal_i = len(self.seal_list)-1

        if not(last_seal.b.includes_lit('f')):
            warnings.warn(f"SEAL record #{seal_i}: Digest byte range ends at: \'{last_seal.b.str_end()}\', should be \'f\' for full coverage")

