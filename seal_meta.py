from typing import Optional as Opt, Self, Any, Protocol, cast, get_type_hints
from Crypto.Hash import SHA256, SHA512, SHA1
import Crypto.PublicKey.RSA as RSA
from Crypto.Signature import pkcs1_15
from seal_models import  (SealByteRange, SealSignature, SealSignatureFormat, SealKeyVersion, SealUID, SealBase64,
						  KEY_ALGS_T, KEY_ALGS, DA_ALGS_T, DA_ALGS, get_fields, clean_str, format_str)


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

	
	def da_hash(self, file_bytes: bytes) -> Hash:
		if self.da == "sha1":
			return SHA1.new(file_bytes)
		elif self.da == "sha256":
			return SHA256.new(file_bytes)
		elif self.da == "sha512":
			return SHA512.new(file_bytes)
		raise RuntimeError("Invalid digest algorithm: "+self.da)

	def ka_verify(self, public_key: SealBase64, digest: Hash) -> bool:
		if self.ka == "rsa":
			rsa_key = RSA.import_key(public_key.val)
			try:
				pkcs1_15.new(rsa_key).verify(digest, self.s.sig_b)
				return True
			except (ValueError, TypeError):
				return False
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