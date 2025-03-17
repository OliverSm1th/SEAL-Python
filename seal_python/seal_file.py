from io import BufferedReader as File
from os import path as os_path
from shutil import move as os_move
import re
from typing import List, Tuple, Optional as Opt, NamedTuple, Dict
import warnings
from .seal_models import BytePos, SealByteRange
from .seal_meta import SealMetadata, SealVerifyData, SealSignData_F
from .seal_signer import SealSigner
from .seal_verify import verify_seal
from .log import log, set_debug

# Stores the positions and metadata for the SEAL entries

class SealEntry(NamedTuple):
    start: int
    end:   int
    seal:  SealMetadata

class SealFile():
    r_file:         File
    r_file_path:    str
    seal_arr:       List[SealEntry]
    saved_pos:      Dict[str, int]
    is_finalised:   bool
    
    def __init__(self, path: str, debug=False):
        self.r_file_path = path
        self.r_file = open(path, "rb")
        # Initial Values:
        self.seal_arr     = []
        self.saved_pos    = {}
        self.is_finalised = False
        if debug:   set_debug(debug)

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
        return self.read_seal_str(block_str, block_start)
        
        
    def read_seal_str(self, seal_str: str, block_start: int) -> Tuple[bool, Opt[SealMetadata]]:
        try:
            seal = SealMetadata.fromWrapper(seal_str)    # Throws ValueError if improperly structured
        except ValueError as e:  
            warnings.warn(f"  Invalid SEAL structure- {str(e)}")
            return (False, None)

        # Check the range is positioned correctly
        isFirst = len(self.seal_arr) == 0
        seal.b.check(isFirst)
    
        # Get signature start + end pos (S+s)
        (S, s) = get_offsets(seal_str)
        log(f"Byte range: {S} -> {s}")

        self.seal_arr.append(SealEntry(block_start + S, block_start + s,seal))

        if self.is_finalised: raise ValueError(f"File is already finalised, cannot include any extra signatures")
        digest_bytes = self.fetch_byte_range(seal.b)
        if seal.s:
            log(f"Signature ({seal.sf}): {seal.s}")

        hash = seal.da_hash(digest_bytes)
        seal_v = SealVerifyData.fromData(seal)

        try:
            verify_seal(seal_v, hash)              # Throws ValueError if invalid
        except ValueError as e:
            warnings.warn(f"  Invalid SEAL- {str(e)}")
            self.seal_arr.pop()  # Remove invalid SEAL recordseal_num-1
            return (False, seal)  
        return (True, seal)
    
    def sign_seal_data(self, seal_data: SealSignData_F, signer: SealSigner) -> SealMetadata:
        # Fetch byte range:
        digest_bytes = self.fetch_byte_range(seal_data.b)
        digest_hash = seal_data.da_hash(digest_bytes)

        signature = signer.sign(seal_data, digest_hash)
        return SealMetadata.fromData(seal_data, sig=signature)


    def insert_seal(self, head: bytes, seal: SealMetadata, foot: bytes, new_path: str = "", overwrite: bool = False):
        """Inserts the block containing the seal metadata at the current position. Also updates seal_arr with the metadata

        Args:
            head (bytes):               Binary data inserted before the seal metadata
            seal (SealMetadata):        Seal Metadata object for updating seal_arr
            foot (bytes):               Binary data inserted afterwards
            new_path (str, optional):   The path for the new file (if empty, rewrite current file)
            overwrite (bool, optional): Overwrite existing seal block at this position
        """
        self.insert_seal_block(head + seal.toWrapper().encode() + foot, seal, len(head), new_path, overwrite)


    def insert_seal_block(self, data_b: bytes, seal: SealMetadata, seal_data_offset: int,  new_path: str = "", S_i: int = -1) -> int:
        cur_pos = self.r_file.tell()

        if S_i > -1 and S_i < len(self.seal_arr):
            overwrite = True
        else:
            overwrite = False    

        # Add the data to the file
        self.insert(data_b, new_path, overwrite)
        
        # Add the seal metadata to seal_arr
        seal_str = seal.toWrapper()
        (S, s) = get_offsets(seal_str)

        seal_entry = SealEntry(S + cur_pos + seal_data_offset, s + cur_pos +seal_data_offset, seal)
        if overwrite:  # Remove the old metadata at the same position
            log(f"   Overwriting SEAL entry #{S_i}  ({seal_entry.start}:{seal_entry.end})")
            self.seal_arr[S_i] = seal_entry
            return S_i
        else:
            log(f"   Inserting new SEAL entry #{len(self.seal_arr)}  ({seal_entry.start}:{seal_entry.end})")
            self.seal_arr.append(seal_entry)
            return len(self.seal_arr) - 1


    def insert(self, bytes: bytes, new_path: str = "", overwrite: bool = False):
        """Create a new file with the given bytes inserted at the current position.

        Args:
            bytes (bytes)
            new_path (str): The path for the new file (if empty, rewrite old file)

        Raises:
            OSError if unable to open the new file
            BlockingIOError if unable to write to the file
        """
        # https://stackoverflow.com/questions/18838919/append-to-a-file-after-nth-byte-in-python
        cur_pos = self.r_file.tell()
        self.r_file.seek(0,0)   # Move to start

        
        w_file_path = new_path if len(new_path) > 0 else SealFile.find_unique_path(self.r_file_path)
        log(f"Reading from: {self.r_file_path}")
        log(f"Writing to: {w_file_path}")
        w_file = open(w_file_path, 'wb')
        w_file.write(self.r_file.read(cur_pos))  # Copy file up to the current point
        w_file.write(bytes)
        if overwrite: self.r_file.seek(len(bytes), 1)
        w_file.write(self.r_file.read())
        w_file.close()
        
        
        self.r_file.close()
        if len(new_path) == 0: # Move w_file to r_file_path
            log(f"Moving {w_file_path} -> {self.r_file_path}")
            os_move(w_file_path, self.r_file_path)
            w_file_path = self.r_file_path

        # Replace r_file with the new file (allow for incremental writes)
        self.r_file = open(w_file_path, "rb")
        self.r_file_path = w_file_path

        # Shift all positions in self.seal_arr and self.saved_pos if needed
        shift = len(bytes)
        for entry_i, entry in enumerate(self.seal_arr):
            if max(entry.end, entry.start) < cur_pos: continue
            e_start = entry.start
            e_end   = entry.end
            if entry.end > cur_pos:    e_end += shift
            if entry.start > cur_pos:  e_start += shift
            log(f"Shifting ({entry.start, entry.end}) -> ({e_start, e_end})")
            self.seal_arr[entry_i] = SealEntry(e_start, e_end, entry.seal)
        
        for key, value in self.saved_pos.items():
            if value >= cur_pos:        value += shift
            log(f"Shifting {key} ({value-shift}) -> ({value})")
            self.saved_pos[key] = value
        self.r_file.seek(cur_pos, 0)
        
    def save_pos(self, key: str, offset: int = 0) -> None:
        self.saved_pos[key] = self.r_file.tell() + offset
    
    def load_pos(self, key: str) -> bool:
        if not key in self.saved_pos: return False
        self.r_file.seek(self.saved_pos[key], 0)
        return True
    
    def reset(self) -> None:
        self.r_file.seek(0,0)

    def fetch_byte_range(self, br: SealByteRange, S_i: int = 0) -> bytes:
        prev_pos = self.r_file.tell()
        digest_bytes : bytes = b''

        write_block = S_i == len(self.seal_arr)
        if write_block:
            S_i = prev_pos

        for (start, end) in br.byte_range:
            start_pos = self._file_pos(start, S_i, write_block)
            end_pos   = self._file_pos(end,   S_i, write_block)
            self.r_file.seek(start_pos, 0 if start_pos>=0 else 2) # 0 = From Start, 2 = From End
            if end_pos >= 0:    # Read up to the required position
                result = self.r_file.read(end_pos-start_pos)
            else:               # Read the rest of the file + remove the required offset
                result = self.r_file.read(-1)
                result[:end_pos+1]
            digest_bytes += result
        self.r_file.seek(prev_pos, 0)
        
        return digest_bytes

    def _file_pos(self, bp: BytePos, S_i: int, write_block: bool = False) -> int:
        # TODO: Remove
        # When reading, S_i is the number of the current SEAL block which Ss refers to
        # When writing, S_i is the position of the insert point as the block hasn't been added yet (write_block=True)
        seal_num = len(self.seal_arr)

        if write_block:
            if bp.literal in "Ss":  # Block hasn't been added, use insert position
                return S_i + bp.offset
            S_i = 0 # For Pp so it refers to the last block in the array

        if bp.literal in 'Ss' and (S_i >= seal_num or seal_num==0):
            raise RuntimeError(f"Invalid byte pos: {bp.literal} for SEAL block #{S_i}, block not added yet (size={seal_num})")
        if bp.literal in 'Pp' and seal_num == 0:
            raise RuntimeError(f"Invalid byte pos: {bp.literal} for SEAL block #{S_i}, no previous signature yet")
        
        # Replaces match case: (Support for Python <3.10)
        cur_pos: int=0
        lit = bp.literal
        if   lit=='F': cur_pos=0
        elif lit=='f': cur_pos=-1
        elif lit=='S': cur_pos=self.seal_arr[S_i].start
        elif lit=='s': cur_pos=self.seal_arr[S_i].end
        elif lit=='P': cur_pos=self.seal_arr[S_i-1].start
        elif lit=='p': cur_pos=self.seal_arr[S_i-1].end

        return cur_pos + bp.offset

    @staticmethod
    def find_unique_path(path: str) -> str:
        if not os_path.exists(path): return path
        i = 1
        # Remove file extension
        path_ = ".".join(path.split(".")[:-1])
        ext   = path.split(".")[-1]

        while os_path.exists(f"{path_}-{i}.{ext}"):
            i +=1
        return f"{path_}-{i}.{ext}"


    # ---Not Used/Broken--
    def _last_seal(self) -> Opt[SealMetadata]:
        i = len(self.seal_arr)-1
        if len(self.seal_arr) > 0:
            return self.seal_arr[-1].seal
        return None

    def end_verify(self):
        last_block = self.seal_arr[-1]
        last_seal  = last_block[-1]
        seal_i = len(self.seal_arr) - 1

        if not(last_seal.b.includes_lit('f')):
            warnings.warn(f"SEAL record #{seal_i}: Digest byte range ends at: \'{last_seal.b.str_end()}\', should be \'f\' for full coverage")

def get_offsets(seal_str: str, d_digest: bool = False) -> Tuple[int, int]:
		"""Get the start and end position of the signature excluding any quotation marks
		i.e: <seal...s="~sig~"/>   (~ = S,s)

		Args:
			seal_str (str) \n
			d_digest (bool): 
				True = Exclude any date or user from the signature range  i.e: <seal...s="date:user:~sig~"/>
				False = Include them in the signature range i.e: <seal...s="~date:user:sig~"/>

		Returns:
			Tuple[int, int]: _description_
		"""
		S = seal_str.index(" s=") + 3
		
		s = len(seal_str) - 2
		if seal_str[S] == seal_str[s-1] and seal_str[S] in ['\'', '\"']:  
			S += 1; s -= 1
		
		if seal_str[S:s].count(':') > 0 and d_digest:	# Move signature start past date + user:    date:user:_sig
			S += seal_str[S:s].rfind(':') + 1
		return (S, s)