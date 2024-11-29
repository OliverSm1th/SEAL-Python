import hashlib
from typing import cast, Literal as Lit, Optional as Opt, Any, get_type_hints, get_args, List, Tuple, NamedTuple, Self
import re
import base64
from binascii import Error as BinError
from datetime import datetime
import warnings
import rsa

# TEMP:
def warning_format(msg, category, filename, lineno, line=None):
	return f"WARNING: {msg}\n"
warnings.formatwarning = warning_format

KA = ['rsa', 'ec']

BYTE_LIT_ORDER = "FPpSsf"

class BytePos(NamedTuple):
	literal: str
	offset: int

	is_start: bool
	
		
	@classmethod
	def from_str(obj, part, is_start):
		if len(part) == 0: 	literal = 'F' if is_start else 'f'
		else: 				literal = part[0]
		offset = 0

		if len(part) > 1:
			if len(part) > 2 and part[2:].isnumeric() and part[1] in ['+', '-']:
				offset = int(part[2:])
			else:
				raise ValueError(f"Invalid ByteRange part \'{part}\', each part must be of the form: [literal]+/-[num]")
			
			if part[1] == '-': offset *= -1
		return obj(literal, offset, is_start)
	
	def check_valid(self): # Checks for basic errors without any other context
		if self.literal == '': self.literal = 'F' if self.is_start else 'f'

		if not self.literal in BYTE_LIT_ORDER: raise ValueError("Invalid ByteRange, invalid literal "+self.literal)
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

	def __init__(self, byte_range: str):
		self.str_byte_range = byte_range
		self.byte_range = self._get_range(byte_range)	

	@staticmethod
	def _get_range(str_byte_range: str) -> List[Tuple[BytePos, BytePos]]:
		values : List[Tuple[BytePos, BytePos]] = []

		positions: List[BytePos] = [] 
		for range in str_byte_range.split(','):
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
					values.append((prev_pos, cur_pos))
		return values
	
	def _flatten(self) -> List[BytePos]:
		arr : List[BytePos] = []
		for range in self.byte_range:
			arr.extend(range)
		return arr

	
	def overlaps(a, b: Self) -> bool:
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
	
	
	def includes_lit(self, lit: str, allow_offset: bool = False) -> bool:
		for byte_pos in self._flatten():
			if byte_pos.literal == lit and (allow_offset or byte_pos.offset == 0):
				return True
		return False

	def str_start(self) -> str:
		return str(self.byte_range[0][0])
	
	def str_end(self) -> str:
		return str(self.byte_range[-1][1])

	def __str__(self) -> str:
		return self.str_byte_range
	

class SealSignature(NamedTuple):
	sig_b: bytes
	sig_d: Opt[datetime] = None


VALID_SIG_FORMATS = Lit["hex", "HEX", "base64", "bin"]
class SealSignatureFormat:
	date_format: Opt[int] = None
	signature_format: VALID_SIG_FORMATS
	
	def __init__(self, sf: str) -> None:
		signature_format = sf
		sep_num = sf.count(':')

		if(sep_num > 1 or sep_num < 0):
			raise ValueError("Signature format must be of form 'date[0-9]:format' or 'format'")

		if(sep_num == 1):  # Includes a date specifier
			[date_format, signature_format] = sf.split(':')
			if not(re.match("^date[0-9]?$", date_format)):
				raise ValueError("Invalid date format, should be of the form: 'date[0-9]'")
			
			self.date_format = cast(int, date_format[4]) if len(date_format) == 5 else 0

		if not(re.match("^(hex|HEX|base64|bin)$", signature_format)):
			raise ValueError("Invalid signature format, should be one of: 'hex', 'HEX', 'base64', 'bin'")
		self.signature_format = cast(VALID_SIG_FORMATS, signature_format)
	
	def sig_bytes(self, s: str) -> bytes:
		sf = self.signature_format
		if sf == "base64":
			no_pad = re.sub('[\\s]+$', '', s)
			return SealBase64.to_bytes(no_pad)
		elif sf == "bin":
			if not(re.match("^[01]+$", s)): 
				raise ValueError("Invalid binary signature, must only contain 0 or 1")
			return int(s, 2).to_bytes((len(s)+7)//8)  # From https://stackoverflow.com/a/32676625
		elif sf in ["hex", "HEX"]:
			m = "a-f" if sf == "hex" else "A-F"
			if not(re.match(f"^[0-9{m}]+$", s)):
				raise ValueError(f"Invalid hex signature, must only contain the following characters: [0-9{m}]")
			if len(s)%4 != 0:
				raise ValueError(f"Invalid hex signature, must be a two-byte hex (len divisible by 4)")
			return bytes.fromhex(s.upper())
		return bytes()
	
	def sig_str(self, b: bytes) -> str:
		sf = self.signature_format
		if sf == "base64":
			return base64.b64encode(b).decode('ascii')
		elif sf=="bin":
			return bin(int.from_bytes(b))[2:]
		elif sf in ["hex", "HEX"]:
			hex = b.hex()
			return hex if sf == "hex" else hex.upper()
		return ""
	
	def date_f_str(self):  # Date format string (for errors)
		# YYYYMMDDhhmmss.[date_format]
		return "YYYYMMDDhhmmss"+ ("."+"f"*self.date_format if self.date_format>0 else "")

	def date_len(self):
		if self.date_format is None or self.date_format <= 0:
			return 14
		else:
			return 14 + 1 + self.date_format


	def construct_sig(self, s:str) -> SealSignature:
		sig_str = s
		sig_date = None
		if self.date_format is not None:
			if s.count(':') != 1:
				raise ValueError("Invalid signature, does not match signature format (date:signature)")
			[date_str, sig_str] = s.split(':')
						
			date_len = self.date_len()

			
			if len(date_str) != date_len or (self.date_format > 0 and s[14] != '.'):
				raise ValueError(f"Invalid signature, date does not match the expected format: {self.date_f_str()}")
			
			date_long = date_str + ('.' if self.date_format == 0 else '')
			date_long = date_long.ljust(21, '0')  # 14 + 1 + 6
			try:
				sig_date = datetime.strptime(date_long, "%Y%m%d%H%M%S.%f")
			except ValueError as e:
				if "does not match format" in str(e):
					raise ValueError(f"Invalid signature, date \'{date_str}\' does not match the expected format: {self.date_f_str()}")
				else: raise e

		sig_b = self.sig_bytes(sig_str)

		return SealSignature(sig_b, sig_date)

	def convert_sig(self, sig: SealSignature) -> str:
		sig_str = self.sig_str(sig.sig_b)
		if sig.sig_d is not None:
			sig_date_s = sig.sig_d.strftime("%Y%m%d%H%M%S.%f")
			if self.date_format is None or self.date_format == 0:
				sig_date_s = sig_date_s[:self.date_len()]
			sig_str = sig_date_s + sig_str
		return sig_str

	def __str__(self) -> str:
		output = ""
		if(self.date_format != None):
			output += "date"+str(self.date_format)+":"
		output += self.signature_format
		return output
	

class SealKeyVersion:
	key_version: str
	def __init__(self, kv: str):
		if not(re.match("^[A-Za-z0-9.+\\/-]+$", kv)):
			raise ValueError("Key version can only contain the following characters: [A-Za-z0-9.+/-]")
		self.key_version = kv
	def __str__(self) -> str:
		return self.key_version

class SealUID:
	uid: str
	def __init__(self, uid: str):
		if not(re.match("^[^\"\'\\s]+$|^$", uid)):
			raise ValueError("Unique identifier cannot include the following characters: [\"\'] or any whitespace")
		self.uid = uid
	def __str__(self) -> str:
		return self.uid

class SealBase64:
	val: bytes
	def __init__(self, str_64: str):
		str_val = re.sub('[\"\\s]', '', str_64)
		self.val = SealBase64.to_bytes(str_val)
	
	@staticmethod
	def to_bytes(str_64: str) -> bytes:
		str_val = re.sub('={0,2}$', '', str_64)
		str_val_pad = str_val + '='*(4-len(str_val)%4)

		try:
			return base64.b64decode(str_val_pad, validate=True)
		except BinError as e:
			raise ValueError("Invalid base64: \""+str_val_pad+" ("+str(e)+")") from None

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

KEY_ALGS_T = Lit['rsa']
KEY_ALGS = get_args(KEY_ALGS_T)

DA_ALGS_T = Lit[ 'sha256', 'sha512', 'sha1']
DA_ALGS = get_args(DA_ALGS_T)

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


class SealMetadata():
	# Required:
	seal: int					# SEAL Version
	ka:   KEY_ALGS_T   			# Key Algorithm
	s:    SealSignature         # Signature
	d:	  str					# Domain Name

	# Optional:  (with default values)
	kv:   SealKeyVersion		# Key Version
	da:   DA_ALGS_T				# Digest Algorithm
	b:    SealByteRange	 		# Digest Byte Range
	uid:  SealUID				# UUID/Date
	sf:   SealSignatureFormat	# Signature Format
	#             (no default)
	id:   Opt[str]  			# Account identifier
	copyright: Opt[str]			# Copyright information
	info: Opt[str]				# Textual comment information
	sl:   Opt[int] 				# Signature Length (not implemented)

	def __init__(self,	seal: int,			ka:  str,			s:  str,
			  			d:    str, 			kv:  str="1",		da: str='sha256',
						b:    str="F~S,s~f",uid: str="",		sf: str='base64',
						id:   Opt[str]=None,		copyright: 	Opt[str]=None,
						info: Opt[str]=None,		sl:			Opt[int]=None):
		self.d  = d
		if ka in KEY_ALGS:  self.ka = cast(KEY_ALGS_T, ka)
		else: raise ValueError("Invalid key algorithm: "+ka)
		self.seal = seal
		self.kv = SealKeyVersion(kv)
		if da in DA_ALGS: 	self.da = cast(DA_ALGS_T, da)
		else:  raise ValueError("Invalid key version: "+kv)
		self.b   = 	SealByteRange(b)
		self.uid = 	SealUID(uid)
		self.sf  = 	SealSignatureFormat(sf)
		self.s   =  self.sf.construct_sig(s)

		self.id = id
		self.copyright = copyright
		self.info = info
		self.sl = sl  # (not implemented)

	@classmethod
	def fromEntry(obj, meta_str: str):
		meta_dict : dict[str, Any] = {}
		meta_struct = get_type_hints(obj)
		fields = get_fields(meta_str)

		for field in fields:
			[key, val] = field
			if not key in meta_struct:
				raise ValueError(f"Unexpected key in SEAL string: \'{key}\'")
			value = clean_str(val)

			if key in ['seal', 'sl']:
				if not value.isnumeric():
					raise ValueError(f"Invalid integer value for \'{key}\' in SEAL string: \'{value}\'")
				else:
					meta_dict[key] = int(value)
			else: 	meta_dict[key] = value
		
		# Check Required:
		required = {'seal': 'SEAL version', 'ka': 'Key Algorithm', 's': 'signature', 'd': 'domain name'}
		for key in required:
			if not key in meta_dict: raise ValueError(f"Missing {meta_dict[key]} ({key})")

		return obj(**meta_dict)
	
	def toEntry(self) -> str:
		options = []
		attr_dict = self.__dict__
		
		attr_order = list(attr_dict.keys())
		
		attr_order.sort(key=lambda k: -1 if k == 'seal' else 99999 if k == 's' else len(str(attr_dict[k])))

		for attr in attr_order:
			if attr == 's':
				str_val = self.sf.convert_sig(self.s)
			elif attr_dict[attr] == None:
				continue
			else:
				str_val = str(attr_dict[attr])
				if len(str_val) == 0: continue
				str_val = format_str(str_val)
			
			options.append(attr + "=" + str_val)
		return ' '.join(options)

	
	def da_hash(self, digest_bytes: bytes) -> bytes:
		if self.da == "sha1":
			return hashlib.sha1(digest_bytes).digest()
		elif self.da == "sha256":
			return hashlib.sha256(digest_bytes).digest()
		elif self.da == "sha512":
			return hashlib.sha512(digest_bytes).digest()
		raise RuntimeError("Invalid digest algorithm: "+self.da)

	def ka_decrypt(self, public_key: SealBase64) -> bytes:
		if self.ka == "rsa":
			p_key = rsa.PrivateKey.load_pkcs1(public_key.val, "DER")
			return rsa.decrypt(self.s.sig_b, p_key)
		raise RuntimeError("Invalid key algorithm: "+self.ka)
			
	def __str__(self) -> str:
		

		options = []
		attr_dict = self.__dict__
		
		attr_order = list(attr_dict.keys())
		
		attr_order.sort(key=lambda k: -1 if k == 'seal' else 99999 if k == 's' else len(str(attr_dict[k])))

		for attr in attr_order:
			if attr == 's':
				str_val = self.sf.convert_sig(self.s)
			elif attr_dict[attr] == None:
				continue
			else:
				str_val = str(attr_dict[attr])
				if len(str_val) == 0: continue
				str_val = format_str(str_val)
			
			options.append(attr + "=" + str_val)
		return ' '.join(options)

class SealDNS():
	# Required:
	seal: 	int					# SEAL Version
	p:		Opt[SealBase64]		# Base64 Public Key  (None=revoke)
	ka:   	KEY_ALGS_T			# Key Algorithm
	
	# Optional: (with default values)
	kv:		SealKeyVersion		# Key Version
	uid: 	SealUID				# UUID/Date
	#			(no default)
	r:		Opt[SealTimestamp]	# Revocation Date (in GMT)

	def __init__(self,  seal: int,	p: Opt[str],	ka: str = 'rsa',  
						kv: str = "1", 		uid:  str = "",
						r:  Opt[str] = None 	):
		self.seal = seal
		if p is not None and p.strip() != "revoke" and len(p.strip()) > 0:
			self.p = SealBase64(p)
		else: 				# All instances of this public key is revoked
			self.p = None

		if ka in KEY_ALGS:  self.ka = cast(KEY_ALGS_T, ka)
		else: raise ValueError("Invalid key algorithm: "+ka)
		self.kv = SealKeyVersion(kv)
		self.uid = SealUID(uid)
		if r is not None:	# All signatures after the date is invalid
			self.r = SealTimestamp(r)

	@classmethod
	def fromEntry(obj, dns_str: str):
		dns_dict : dict[str, Any] = {}
		dns_struct = get_type_hints(obj)
		fields = get_fields(dns_str)

		for field in fields:
			[key, val] = field
			if not key in dns_struct:
				raise ValueError("Unexpected key in DNS string: "+key)
			value = clean_str(val)
			
			if key == 'seal': 	
				if not value.isnumeric():
					raise ValueError(f"Invalid integer value for \'{key}\' in SEAL string: \'{value}\'")
				else:
					dns_dict[key] = int(value)
			else: 	dns_dict[key] = value

		required = {'seal': 'SEAL version', 'ka': 'Key Algorithm'}
		
		for key in required:
			if not key in dns_dict: raise ValueError(f"Missing {dns_dict[key]} ({key})")

		return obj(**dns_dict)

	def __str__(self) -> str:
		options = []
		attr_dict = self.__dict__
		
		attr_order = list(attr_dict.keys())
		attr_order.sort(key=lambda k: -1 if k == 'seal' else 99999 if k == 'p' else len(str(attr_dict[k])))

		for attr in attr_order:
			if attr_dict[attr] != None:
				str_val = str(attr_dict[attr])
				if len(str_val) == 0: continue
				options.append(attr + "=" + str_val)
		return ' '.join(options)