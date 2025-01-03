from io import BufferedReader as File
import re
from typing import List, Tuple, Optional as Opt
import warnings
from seal_models import BytePos, SealByteRange
from seal_meta import SealMetadata
from seal_verify import verify_seal

# Stores the positions and metadata for the SEAL entries

class SealFile():
    file:           File
    seal_pos:       List[Tuple[int, int]]    = []
    seal_arr:       List[SealMetadata]       = []
    is_finalised:   bool                     = False

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
            # print(f"{start_pos} -> {end_pos}")
            self.file.seek(start_pos, 0 if start_pos>=0 else 2) # 0 = From Start, 2 = From End
            if end_pos >= 0:    # Read up to the required position
                result = self.file.read(end_pos-start_pos)
            else:               # Read the rest of the file + remove the required offset
                result = self.file.read(-1)
                result[:end_pos+1]
            digest_bytes += result
            # print("="*20)
            # print(result)
        self.file.seek(prev_pos, 0)
        
        return digest_bytes


    def _verify_seal_str(self, seal_str: str) -> SealMetadata:
        """Parses and validates a SEAL string 

        :param seal_str: _description_
        :type seal_str: str
        :return: _description_
        :rtype: SealMetadata
        """
        seal = SealMetadata.fromEntry(seal_str)  # Throws ValueError if invalid structure

        #  Assumes SEAL records are ordered in increasing byte ranges:
        if len(self.seal_pos) == 0:
            if not(seal.b.includes_lit('F')):
                warnings.warn(f"Digest byte range starts at: \'{seal.b.str_start()}\', should be \'F\' for full coverage")
        else:
            if not(seal.b.includes_lit('F') or seal.b.includes_lit('P')):
                warnings.warn(f"Digest byte range starts at: \'{seal.b.str_start()}\', should be \'F\' or \'P\' for full coverage")

        # Fetch byte range:
        digest_bytes = self.fetch_byte_range(seal.b)

        # Verify:
        verify_seal(seal, digest_bytes)         # Throws ValueError if invalid
        
        return seal

    def read_seal_str(self, seal_wrap: str) -> SealMetadata:
        # Wrapper can be one of:
        # seal:seal<seal ..>
        # </seal:seal>
        # <seal:seal seal='<seal ...>'/>
        # <rdf ...

        if not re.match("^<((\\*:)|\\?)?seal ", seal_wrap):
            raise ValueError(f"Not a valid SEAL string. Must be be of the form: <seal .../>")
        
        if not (seal_wrap.endswith("/>")):
            raise ValueError(f"Missing XML end '/>'")
    

        
        if self.is_finalised:
            raise ValueError(f"File is already finalised, cannot include any extra signatures")
        
        seal_str = seal_wrap[seal_wrap.index("seal")+5:-2]
        # TODO: Sort out block/wrapper (can you have >1 wrapper per block???)

        return self._verify_seal_str(seal_str)



    def _last_seal(self) -> Opt[SealMetadata]:
        i = len(self.seal_arr)-1
        if len(self.seal_arr) > 0:
            return self.seal_arr[-1]
        return None

    # Not used (can't have multiple SEAL signatures per block)
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
                seal = self._read_seal_str(seal_str)
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


    def read_txt_block(self, block_len: int) -> bool:
        block_start = self.file.tell()

        block_bytes = self.file.read(block_len)
        block_str   = str.strip(block_bytes.decode())        

        if not re.match("^<((\\*:)|\\?)?seal ", block_str):
            return False
        
        S = block_str.index(" s=") + 3
        s = len(block_str) - 3
        if block_str[S] == block_str[s] and block_str[S] in ['\'', '\"']: S += 1; s -= 1
        self.seal_pos.append((block_start + S,
                              block_start + s + 1))

        
        seal_i = len(self.seal_arr)
        print(f"---SEAL #{seal_i}---")
        
        try:
            seal_valid = self.read_seal_str(block_str)
        except ValueError as e:  # Not a valid SEAL block, remove position from seal_pos
            self.seal_pos.pop()  # TODO: Do you remove the reference if it fails?
            warnings.warn(f"  Invalid record- {str(e)}, skipping")
            return False
    
        
        self.seal_arr.append(seal_valid)
        return True

    def write_seal(self, seal: SealMetadata) -> bool:
        

        return False


    def end_verify(self):
        last_block = self.seal_arr[-1]
        last_seal  = last_block[-1]
        seal_i = self.seal_arr_i[-1] + len(last_block) - 1

        if not(last_seal.b.includes_lit('f')):
            warnings.warn(f"SEAL record #{seal_i}: Digest byte range ends at: \'{last_seal.b.str_end()}\', should be \'f\' for full coverage")

