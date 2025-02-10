from datetime import datetime
import re
from typing_extensions import Any, Self   # Allows < Python3.11 to work 
from typing import NamedTuple, Optional as Opt, Protocol, Tuple, cast, get_type_hints
from Crypto.Hash import SHA256, SHA512, SHA1
import Crypto.PublicKey.RSA as RSA
from Crypto.Signature import pkcs1_15
from .seal_models import  (SealByteRange, SealSignature, SealSignatureFormat, SealKeyVersion, SealUID, SealBase64,
						  KEY_ALGS_T, KEY_ALGS, DA_ALGS_T, DA_ALGS, get_fields, clean_str, format_str)

# Default Values:
SEAL_DEF = 1

# KA_DEF = "rsa"
# KV_DEF = "1"
# DA_DEF = "sha256"
# B_DEF  = "F~S,s~f"
# UID_DEF= ""
# SF_DEF = "base64"
DEF = {
	"ka" : "rsa",
	"kv" : "1",
	"da" : "sha256",
	"b"  : "F~S,s~f",
	"uid": "",
	"sf" : "base64"
}

REQ = {
	'seal': 'SEAL version', 
	'ka': 'Key Algorithm', 
	's': 'signature', 
	'd': 'domain name'
}

# Structure of Cryto.Hash objects (i.e SHA256/512/1):
class Hash(Protocol):
	digest_size: int
	block_size: int
	oid: str
	def __init__(self, data=None) -> None: ...
	def copy(self) -> Self: ...
	def digest(self) -> bytes: ...
	def hexdigest(self) -> str: ...
	def new(self,data=None) -> Self: ...
	def update(self,data:bytes|bytearray|memoryview) -> None: ...

class SealSignData(NamedTuple):
	"""All data provided by the user for signing"""
	# Required:
	d:	  str					# Domain Name

	# Optional: (with default values)
	ka:   KEY_ALGS_T = DEF['ka']  	# Key Algorithm
	kv:   str		 = DEF['kv']	# Key Version
	da:   DA_ALGS_T	 = DEF['da']	# Digest Algorithm
	uid:  str		 = DEF['uid']	# UUID
	sf:   str		 = DEF['sf']	# Signature Format
	#             (no default)
	id:   		Opt[str] = None # Account identifier
	copyright: 	Opt[str] = None	# Copyright information
	info: 		Opt[str] = None	# Textual comment information
	sl:   		Opt[int] = None	# Signature Length (not implemented)

	def check(self):
		if not self.ka in KEY_ALGS: raise ValueError("Invalid key algorithm: "+self.ka)
		SealKeyVersion.check(self.kv)
		if not self.da in DA_ALGS:  raise ValueError("Invalid key algorithm: "+self.da)
		SealUID.check(self.uid)
		SealSignatureFormat.check(self.sf)


class SealMetadata():
	# Required:
	seal: int					# SEAL Version		(!)
	d:	  str					# Domain Name

	# Optional:  (with default values)
	ka:   KEY_ALGS_T   			# Key Algorithm
	kv:   SealKeyVersion		# Key Version
	da:   DA_ALGS_T				# Digest Algorithm
	b:    SealByteRange	 		# Digest Byte Range	(!)
	uid:  SealUID				# UUID/Date
	sf:   SealSignatureFormat	# Signature Format
	#             (no default)
	id:   		Opt[str]  		# Account identifier
	copyright: 	Opt[str]		# Copyright information
	info: 		Opt[str]		# Textual comment information
	sl:   		Opt[int] 		# Signature Length (not implemented)

	# Required for verification, generated while signing
	s:    Opt[SealSignature]    # Signature			(!)


	def __init__(self,	seal: int,			d:    str,
			  
			  			ka:	 KEY_ALGS_T	= DEF['ka'],	kv: str = DEF['kv'],		
						da:  DA_ALGS_T	= DEF['da'],	b: 	str = DEF['b'],
						uid: str		= DEF['uid'],	sf:	str = DEF['sf'],

						id:   Opt[str]	=None,		copyright: 	Opt[str]=None,
						info: Opt[str]	=None,		sl:			Opt[int]=None,
						
						s:    Opt[str]	=None	):
		self.seal = seal
		
		if ka in KEY_ALGS:  self.ka = cast(KEY_ALGS_T, ka)
		else: raise ValueError("Invalid key algorithm: "+ka)

		self.d    = d
		self.kv   = SealKeyVersion(kv)

		if da in DA_ALGS: 	self.da = cast(DA_ALGS_T, da)
		else:  raise ValueError("Invalid key version: "+kv)		
		
		self.b    = SealByteRange(b)
		self.uid  = SealUID(uid)
		self.sf   = SealSignatureFormat(sf)
		self.s    =	SealSignature.fromStr(self.sf, s) if s is not None else s
		self.id   = id
		self.copyright = copyright
		self.info = info
		self.sl   = sl  # (not implemented)
	
	@classmethod
	def fromData(obj, data: SealSignData, seal: int = SEAL_DEF, byte_range: str = DEF['b'], signature: Opt[str] = None) -> Self:
		data_dict = data._asdict()
		data_dict['seal'] = seal
		data_dict['b']    = byte_range
		data_dict['s']    = signature
		return obj(**data_dict)

	@classmethod
	def fromWrapper(obj, wrap_str: str) -> Self:
		if not re.match("^<seal (.)*/>", wrap_str):
			raise ValueError(f"Not a valid SEAL wrapper. Must be be of the form: <seal .../>")
		seal_str = wrap_str[6:-2]
		return obj.fromEntry(seal_str)

	@classmethod
	def fromEntry(obj, meta_str: str) -> Self:
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
		for key in REQ:
			if not key in meta_dict: raise ValueError(f"Missing {REQ[key]} from: {meta_str}")
		return obj(**meta_dict)
	
	def set_signature(self, sig_b: bytes, sig_d: Opt[datetime] = None):
		self.s = SealSignature(self.sf, sig_b, sig_d)
	
	def set_byte_range(self, b: str = DEF['b']):
		self.b = SealByteRange(b)

	def da_hash(self, file_bytes: bytes) -> Hash:
		if self.da == "sha1":
			return SHA1.new(file_bytes)
		elif self.da == "sha256":
			return SHA256.new(file_bytes)
		elif self.da == "sha512":
			return SHA512.new(file_bytes)
		raise RuntimeError("Invalid digest algorithm: "+self.da)

	def ka_verify(self, public_key: SealBase64, digest: Hash) -> bool:
		"""Use the key algorithm to verify the encrypted digest matches the signature

		Args:
			public_key (SealBase64)
			digest (Hash): From the `Crypt.Hash` package.

		Raises:
			RuntimeError: if the key algorithm or signature is invalid

		Returns:
			bool: True = encrypted digest matches the signature"""
		if self.s is None: raise RuntimeError("No signature set")
		if self.ka == "rsa":
			rsa_key = RSA.import_key(public_key.val)
			try:
				pkcs1_15.new(rsa_key).verify(digest, self.s.sig_b)
				return True
			except (ValueError, TypeError):
				return False
		raise RuntimeError("Invalid key algorithm: "+self.ka)

	def ka_encrypt(self, private_key: SealBase64, digest: Hash) -> bytes:
		"""Use the key algorithm and private key to encrypt the digest

		Args:
			private_key (SealBase64)
			digest (Hash): From the `Cryto.Hash` package.

		Raises:
			RuntimeError: if the key algorithm isn't supported.
			ValueError: if the key is invalid.

		Returns:
			bytes: the encrypted digest"""
		if self.ka == "rsa":
			rsa_key = RSA.import_key(private_key.val)
			try:
				return pkcs1_15.new(rsa_key).sign(digest)
			except ValueError:
				raise ValueError("Key is too short")
			except TypeError:
				raise ValueError("Key provided has no private component")
		raise RuntimeError("Invalid key algorithm: "+self.ka)
	def ka_key_size(self, private_key: SealBase64) -> int:
		if self.ka == "rsa":
			return RSA.import_key(private_key.val).size_in_bits()
		raise RuntimeError("Invalid key algorithm: "+self.ka)
			
	def toEntry(self) -> str:
		return self.__str__()
	
	def toWrapper(self) -> str:
		return f"<seal {self.toEntry()}/>"
	
	def toDict(self) -> dict[str, str]:
		attr_dict = self.__dict__
		str_dict : dict[str, str] = {}
		for key, value in attr_dict.items():
			if value is not None:
				
				str_val = str(value)
				if len(str_val) == 0: continue
				if key in DEF and DEF[key] == str_val and not key in REQ: continue
				str_dict[key] = str_val
		return str_dict
	
	def __str__(self) -> str:
		options = []
		attr_dict = self.toDict()
		
		attr_order = list(attr_dict.keys())
		
		attr_order.sort(key=lambda k: -1 if k == 'seal' else 99999 if k == 's' else len(str(attr_dict[k])))

		for attr in attr_order:
			str_val = format_str(attr_dict[attr])
			
			options.append(attr + "=" + str_val)
		return ' '.join(options)
	

	@staticmethod
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
	
			