from typing import cast, Literal as Lit, Protocol, Optional as Opt, get_args, List, Tuple, Union
from typing_extensions import Self   # Allows < Python3.11 to work 
from Crypto.Hash import SHA256, SHA512, SHA1
from math import log2, floor, ceil

import re
import base64
from binascii import Error as BinError
from datetime import datetime
import warnings

# TEMP:
def warning_format(msg, category, filename, lineno, line=None):
	return f"WARNING: {msg}\n"
warnings.formatwarning = warning_format


# Basic Types:
KEY_ALGS_T = Lit['rsa']
KEY_ALGS = get_args(KEY_ALGS_T)

DA_ALGS_T = Lit[ 'sha256', 'sha512', 'sha1']
DA_ALGS = get_args(DA_ALGS_T)

BIN_FORMATS_T = Lit["hex", "HEX", "base64", "bin"]
BIN_FORMATS = get_args(BIN_FORMATS_T)

# Defaults:
SEAL_DEF = "1"

DA_DEF : DA_ALGS_T 	= "sha256"
KA_DEF : KEY_ALGS_T = "rsa"
KV_DEF : str		= "1"
B_DEF  : str		= "F~S,s~f"
UID_DEF: str		= ""
BIN_DEF : str = "base64"
SF_DEF : str = f"{BIN_DEF}"

# Structure of Cryto.Hash objects (i.e SHA256/512/1):
class Hash(Protocol):
	digest_size: int
	block_size: int
	oid: str
	# def __init__(self, data=None) -> None: ...
	def copy(self) -> Self: ...
	def digest(self) -> bytes: ...
	def hexdigest(self) -> str: ...
	def new(self,data=None) -> Self: ...
	def update(self,data:bytes|bytearray|memoryview) -> None: ...

class DummyHash(Hash):
	digest_size: int
	block_size: int
	oid: str
	data_b: bytes
	def __init__(self, data:bytes, da: DA_ALGS_T) -> None:
		if da == "sha1":
			hash : Hash = SHA1.SHA1Hash()
		elif da == "sha256":
			hash = SHA256.SHA256Hash()
		elif da == "sha512":
			hash = SHA512.SHA512Hash(None, None)
		else:
			raise RuntimeError("Invalid digest algorithm: "+da)
		self.oid = hash.oid
		self.block_size = hash.block_size
		self.digest_size = hash.digest_size
		self.data_b = data
	def digest(self) -> bytes:
		return self.data_b
	def hexdigest(self) -> str:
		return self.data_b.hex()
	def copy(self) -> Self: return self
	def new(self,data=None) -> Self: return self
	def update(self,data:bytes|bytearray|memoryview) -> None: return None
	
		
BYTE_LIT_ORDER = "FPpSsf"

class BytePos:
	literal: str
	offset: int

	is_start: bool
	
	def __init__(self, literal: str, offset: int, is_start: bool):
		self.literal = literal; self.offset = offset; self.is_start = is_start
		
	@classmethod
	def from_str(cls, part, is_start):
		if len(part) == 0: 	literal = 'F' if is_start else 'f'
		else: 				literal = part[0]
		offset = 0

		if len(part) > 1:
			if len(part) > 2 and part[2:].isnumeric() and part[1] in ['+', '-']:
				offset = int(part[2:])
			else:
				raise ValueError(f"Invalid ByteRange part \'{part}\', each part must be of the form: [literal]+/-[num]")
			
			if part[1] == '-': offset *= -1
		return cls(literal, offset, is_start)
	
	def check_valid(self): # Checks for basic errors without any other context
		if self.literal == '': self.literal = 'F' if self.is_start else 'f'

		if not self.literal in BYTE_LIT_ORDER: 		   raise ValueError("Invalid ByteRange, invalid literal "+self.literal)
		if (self.literal == 'F' and self.offset < 0 ): raise ValueError("Invalid ByteRange, cannot be before the file start")
		if (self.literal == 'f' and self.offset > 0 ): raise ValueError("Invalid ByteRange, cannot be after the file end")
		if (self.literal == 'S' and self.offset > 0 or
	  		self.literal == 's' and self.offset < 0):  raise ValueError("Invalid ByteRange, cannot include a signature")
	
	def check_next(self, next : 'BytePos'):
		if next.literal == self.literal:
			if next.offset < self.offset: 
				raise ValueError(f"Invalid ByteRange, {next} cannot be after {self}")
			if next.offset == self.offset and self.is_start:
				raise ValueError(f"Invalid ByteRange, cannot have an empty signature ({self})")

			return
		
		if BYTE_LIT_ORDER.find(next.literal) < BYTE_LIT_ORDER.find(self.literal): raise ValueError(f"Invalid ByteRange, {next} cannot be after {self}")

		if next.literal == 's' or (next.literal == 'f' and self.literal != 's'):   # Going across signature
			if self.is_start: raise ValueError("Invalid ByteRange, cannot include signature")
	


	def __str__(self):
		offset = f'+{self.offset}' if self.offset > 0 else self.offset if self.offset<0 else ""
		return f"{self.literal}{offset}"


class SealByteRange:
	str_byte_range: str
	byte_range: List[Tuple[BytePos, BytePos]]

	def __init__(self, byte_range: str = B_DEF):
		self.str_byte_range = byte_range

		self.byte_range : List[Tuple[BytePos, BytePos]] = []

		positions: List[BytePos] = [] 
		for range in self.str_byte_range.split(','):
			if range.count('~') != 1:
				raise ValueError(f"Invalid ByteRange \'{range}\', must be of the form: start~stop")
			
			[start, end] = range.split('~')
			positions.append(BytePos.from_str(start, True ))
			positions.append(BytePos.from_str(end,   False))
		
		for (i, cur_pos) in enumerate(positions):
			cur_pos.check_valid()
			if(i>0):
				prev_pos = positions[i-1]
				prev_pos.check_next(cur_pos)
				if(i%2 != 0):
					self.byte_range.append((prev_pos, cur_pos))
	
	def _flatten(self) -> List[BytePos]:
		arr : List[BytePos] = []
		for range in self.byte_range:
			arr.extend(range)
		return arr
		
	def includes_lit(self, lit: str, allow_offset: bool = False) -> bool:
		for byte_pos in self._flatten():
			if byte_pos.literal == lit and (allow_offset or byte_pos.offset == 0):
				return True
		return False

	def check(self, isFirst: bool = True):
		if isFirst:
			if not(self.includes_lit('F')):
				warnings.warn(f"Digest byte range starts at: \'{self.str_start()}\', should be \'F\' for full coverage")
		else:
			if not(self.includes_lit('F') or self.includes_lit('P')):
				warnings.warn(f"Digest byte range starts at: \'{self.str_start()}\', should be \'F\' or \'P\' for full coverage")

	def str_start(self) -> str:
		return str(self.byte_range[0][0])
	
	def str_end(self) -> str:
		return str(self.byte_range[-1][1])

	def __str__(self) -> str:
		return self.str_byte_range
	
	# Unused:
	def overlaps(self, a, b: Self) -> bool:
		a_arr = a._flatten()
		b_arr = b._flatten()
		a_i = 0
		b_i = 0

		a_before = None
		while a_i < len(a_arr) and b_i < len(b_arr):
			a_cur = a_arr[a_i]
			b_cur = b_arr[b_i]

			a_lit = a_cur.literal
			b_lit = b_cur.literal
			b_lit = 'S' if b_lit == 'P' else 's' if b_lit == 'p' else b_lit

			if a_lit == b_lit:
				if a_cur.offset < b_cur.offset:
					if a_before == False: return True
					else: 				  a_before = True 
				elif a_cur.offset > b_cur.offset:
					if a_before == True:  return True
					else:				  a_before = False
				else: return True
			else:
				if BYTE_LIT_ORDER.find(a_lit) < BYTE_LIT_ORDER.find(b_lit):
					if a_before == False: return True
					else:				  a_before = True
				else:
					if a_before == True:  return True
					else:				  a_before = False
			
			if(a_before):   a_i += 1
			else:			b_i += 1
		return False


class SealBinaryFormat:
	format: BIN_FORMATS_T
	def __init__(self, format: str=BIN_DEF):
		if not format in BIN_FORMATS:
			raise ValueError("should be one of: \""+("\", \"".join(BIN_FORMATS)+"\""))
		self.format = cast(BIN_FORMATS_T, format)
	
	def binFromStr(self, bin_str: str) -> bytes:
		if self.format == "base64":
			no_pad = re.sub(r'[\s]+$', '', bin_str)
			return b64_to_bytes(no_pad)
		elif self.format == "bin":
			if not(re.match("^[01]+$", bin_str)): 
				raise ValueError("Invalid binary signature, must only contain 0 or 1")
			return int(bin_str, 2).to_bytes((len(bin_str)+7)//8)  # From https://stackoverflow.com/a/32676625
		elif self.format == "hex" or "HEX":
			m = "a-f" if self.format == "hex" else "A-F"
			if not(re.match(f"^[0-9{m}]+$", bin_str)):
				raise ValueError(f"Invalid hex signature, must only contain the following characters: [0-9{m}]")
			if len(bin_str)%4 != 0:
				raise ValueError(f"Invalid hex signature, must be a two-byte hex (len divisible by 4)")
			return bytes.fromhex(bin_str.upper())
		else:
			return bytes()
	def binToStr(self, bin: bytes) -> str:
		return {
			'base64': 	base64.b64encode(bin).decode('ascii'),
			'bin': 		"".join(["{:08b}".format(byte) for byte in bin]),
			'hex':		bin.hex(),
			'HEX':		bin.hex().upper()
		}.get(self.format, "")
	
	def base(self) -> int:
		return {
			'base64': 	64,
			'bin': 		1,
			'hex':		16,
			'HEX':		16
		}.get(self.format, 0)
	
	def __str__(self) -> str:
		return self.format

class SealSignatureFormat:
	date_format: Opt[int] = None
	signature_format: SealBinaryFormat
	
	def __init__(self, sf: str=SF_DEF) -> None:
		sig_str = sf
		sep_num = sf.count(':')

		if(sep_num > 1 or sep_num < 0):
			raise ValueError("Signature format must be of form 'date[0-9]:format' or 'format'")

		if sep_num == 1:  # Includes a date specifier
			[sig_d, sig_str] = sf.split(':')
			if not(re.match("^date[0-9]?$", sig_d)):
				raise ValueError("Invalid date format, should be of the form: 'date[0-9]'")

			self.date_format = int(sig_d[4]) if len(sig_d) == 5 else 0

		try:
			self.signature_format = SealBinaryFormat(sig_str)
		except ValueError as e:
			raise ValueError(f"Invalid signature format \"{sig_str}\", {e}")
	
	def sig_len(self, key_len_bits: int) -> int:
		key_len = floor(key_len_bits / log2(self.signature_format.base()))
		if str(self.signature_format) == "base64":	# Round up to a multiple of 4 for padding
			key_len = ceil(key_len/4)*4
		date_len = self.date_len()
		if date_len > 0:
			return date_len + key_len + 1
		else:
			return key_len


	def __str__(self) -> str:
		output = ""
		if(self.date_format != None):
			output += "date"
			if self.date_format > 0: output += str(self.date_format)
			output += ":"
		output += str(self.signature_format)
		return output

	# Helper functions:
	def date_len(self):  # Length of the date component
		if self.date_format is None:
			return 0
		if self.date_format is None or self.date_format <= 0:
			# date =YYYYMMDDhhmmss     (14)
			return 14	
		else:
			# date1=YYYYMMDDhhmmss.x   (16)
			# date2=YYYYMMDDhhmmss.xx  (17) etc
			return 14 + 1 + self.date_format

	def format_date(self, date: datetime) -> str:
		date_s = date.strftime("%Y%m%d%H%M%S.%f")
		return date_s[:self.date_len()]

	def date_f_str(self):  # String representation of the date format (for errors)
		# date =YYYYMMDDhhmmss
		# date1=YYYYMMDDhhmmss.f  etc
		if self.date_format is None: return ""
		return "YYYYMMDDhhmmss"+ ("."+"f"*self.date_format if self.date_format>0 else "")

	@classmethod
	def check(cls, sf: str):
		# Too complex, might as well do __init__
		result = cls(sf)
		del result


class SealSignature():
	sig_b: bytes		# Binary representation of the signature component 
	date: Opt[datetime]	# Datetime representation of the date component
	sf: SealSignatureFormat  # Format used

	def __init__(self, sig_b: bytes, sf: SealSignatureFormat, date: Opt[datetime] = None):
		self.sf = sf
		self.sig_b = sig_b
		self.date  = date
	
	@classmethod
	def fromStr(cls, sig_str: str, sf: SealSignatureFormat):
		sig_str  = sig_str
		sig_date = None
		# Parse the date
		if sf.date_format is not None:
			if sig_str.count(':') != 1:  raise ValueError("Invalid signature, does not match signature format (date:signature)")
			[date_str, sig_str] = sig_str.split(':')
			
			if len(date_str) != sf.date_len() or (sf.date_format > 0 and date_str[14] != '.'):
				raise ValueError(f"Invalid signature, date does not match the expected format: {sf.date_f_str()}")
			
			# Prepare for parsing
			date_long = date_str + ('.' if sf.date_format == 0 else '')
			date_long = date_long.ljust(21, '0')  # 14 + 1 + 6
			try:
				sig_date = datetime.strptime(date_long, "%Y%m%d%H%M%S.%f")
			except ValueError as e:
				if "does not match format" in str(e):
					raise ValueError(f"Invalid signature, date \'{date_str}\' does not match the expected format: {sf.date_f_str()}")
				else: raise e
		elif sig_str.count(':') > 0:
			raise ValueError("Invalid signature, does not match signature format (signature only)")
		
		# Parse the signature itself
		sig_format = sf.signature_format
		sig_b = sig_format.binFromStr(sig_str)

		return cls(sig_b, sf, sig_date)

	def date_str(self) -> str:
		if self.date is None: 
			return ""
		else:
			return self.sf.format_date(self.date)
	
	def __str__(self) -> str:
		sig_str = self.sf.signature_format.binToStr(self.sig_b)
		if self.date is None:
			return sig_str
		else:
			return self.date_str() + ":" + sig_str

class SealKeyVersion:
	key_version: str
	def __init__(self, kv: str=KV_DEF):
		SealKeyVersion.check(kv)		# Check it's valid
		self.key_version = kv
	def __str__(self) -> str:
		return self.key_version
	def __eq__(self, other: object):
		return isinstance(other, SealKeyVersion) and self.key_version == other.key_version
	@classmethod
	def check(cls, kv: str):
		if not(re.match("^[A-Za-z0-9.+\\/-]+$", kv)):
			raise ValueError("Key version can only contain the following characters: [A-Za-z0-9.+/-]")


class SealUID:
	uid: str
	def __init__(self, uid: str=UID_DEF):
		SealUID.check(uid)
		self.uid = uid
	def __str__(self) -> str:
		return self.uid
	def __eq__(self, other: object):
		return isinstance(other, SealUID) and self.uid == other.uid
	@classmethod
	def check(cls, uid: str):
		if not(re.match("^[^\"\'\\s]+$|^$", uid)):
			raise ValueError("Unique identifier cannot include the following characters: [\"\'] or any whitespace")

def b64_to_bytes(str_64: str) -> bytes:
	str_val = re.sub('={0,2}$', '', str_64)
	pad_len = -len(str_val) % 4
	if pad_len == 3:
		raise ValueError(f"Invalid base64: \"{str_val}\" (invalid length)")
	str_val_pad = str_val + ('=' * pad_len)

	try:
		return base64.b64decode(str_val_pad, validate=True)
	except BinError as e:
		raise ValueError(f"Invalid base64: \"{str_val_pad}\" ({e})") from None

class SealBase64:
	val: bytes
	def __init__(self, str_64: Union[str, bytes]):
		if isinstance(str_64, bytes):
			self.val = str_64
		elif isinstance(str_64, str):
			str_val = re.sub(r'[\"\s]', '', str_64)
			self.val = b64_to_bytes(str_val)
		else: self.val = b''

	def __str__(self) -> str:
		b64 = base64.b64encode(self.val)
		str_b64 = b64.decode('ascii')
		return str_b64


class SealTimestamp:
	time: datetime
	def __init__(self, ts: str):
		str_time = re.sub('[\"]', '', ts)
		try:
			self.time = datetime.fromisoformat(str_time)
		except:
			raise ValueError("Invalid timestamp, must be in ISO 8601 (YYYY-MM-DD) format")
	def __str__(self) -> str:
		return self.time.isoformat()


class SealDigestInfo():
	digest_format:  SealBinaryFormat
	digest_algorithm: DA_ALGS_T
	def __init__(self, digest_format: Opt[str|SealBinaryFormat]=BIN_DEF, digest_algorithm: Opt[str]=DA_DEF) -> None:
		if digest_format is None: raise RuntimeError("Invalid digest format")
		
		try:
			self.digest_format = digest_format if isinstance(digest_format, SealBinaryFormat) else SealBinaryFormat(digest_format)
		except ValueError as e:
			raise ValueError(f"Invalid digest format \"{digest_format}\", {e}")

		da = digest_algorithm
		if not da in DA_ALGS:	raise ValueError("Invalid digest algorithm, should be one of: \""+("\", \"".join(DA_ALGS)+"\""))
		else: da = cast(DA_ALGS_T, da)
		self.digest_algorithm = da
	@classmethod
	def fromStr(cls, d_info: Opt[str]):
		df = None; da = None
		if d_info == None: return cls(None, None)
		if d_info.count(":") == 1:
			(df, da) = d_info.split(":")
		elif d_info in DA_ALGS:
			da = d_info
		elif d_info in BIN_FORMATS:
			df = d_info
		else:
			raise ValueError("Invalid digest info, expecting \"format:algorithm\"")
		return cls(df, da)
	
	def hashToStr(self, hash_b: bytes) -> str:
		return self.digest_format.binToStr(hash_b)
	def hashFromStr(self, hash_s: str) -> bytes:
		da = self.digest_algorithm
		return self.digest_format.binFromStr(hash_s)
		# if da == "sha1":
		# 	hash : Hash = SHA1.SHA1Hash()
		# elif da == "sha256":
		# 	hash = SHA256.SHA256Hash()
		# elif da == "sha512":
		# 	hash = SHA512.SHA512Hash()
		# else:
		# 	raise RuntimeError("Invalid digest algorithm: "+da)
		# return hash.new(hash_b)

	def hash(self, digest_str: str) -> Hash:
		digest_b = self.digest_format.binFromStr(digest_str)
		return SealDigestInfo.hash_b(digest_b, self.digest_algorithm)

	@classmethod
	def hash_b(cls, digest_b: bytes, da: DA_ALGS_T) -> Hash:
		if da == "sha1":
			return SHA1.new(digest_b)
		elif da == "sha256":
			return SHA256.new(digest_b)
		elif da == "sha512":
			return SHA512.new(digest_b)
		raise RuntimeError("Invalid digest algorithm: "+da)
	
	@classmethod
	def dummy_hash(cls, da: DA_ALGS_T, hash_b: bytes) -> DummyHash:
		return DummyHash(hash_b, da)

	def __str__(self) -> str:
		return f"{self.digest_format}:{self.digest_algorithm}"


OPT_QUOT = True	  	# Include quotes even if the value doesn't need them
QUOT_CHR = '\"'		# Quote character (either " or ')

def get_fields(str: str) -> List[List[str]]:   # https://stackoverflow.com/a/24778778
	fields = list(filter(None, re.split(r' (?=(?:[^\'"]*[\'"][^\'"]*[\'"])*[^\'"]*$)', str)))
	return list(map(lambda x: x.split('=', 1), fields))

def clean_str(str: str) -> str:  # Remove quotation marks
	result = str
	for char in ['\'', '\"']:
		if result.startswith(char) and result.endswith(char):
			return result[1:-1]
	return result
def clean_str_(str: Opt[str]) -> Opt[str]:
	if str is None: return None
	else: return clean_str(str)

def format_str(str:str) -> str: # Add quotation marks (if necessary)
	if ' ' in str or OPT_QUOT: 
		return QUOT_CHR + str + QUOT_CHR
	else:
		return str