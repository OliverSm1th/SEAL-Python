from datetime import datetime
import re
from typing_extensions import Any, Self   # Allows < Python3.11 to work 
from typing import Optional as Opt, cast, get_type_hints
import Crypto.PublicKey.RSA as RSA
from Crypto.Signature import pkcs1_15
from .seal_models import  (SealByteRange, SealSignature, SealSignatureFormat, SealKeyVersion, SealUID, SealBase64, SealDigestInfo,
						  KEY_ALGS_T, KEY_ALGS, DA_ALGS_T, DA_ALGS, get_fields, clean_str, format_str, 
						  SEAL_DEF, DA_DEF, KA_DEF, KV_DEF, B_DEF, UID_DEF, SF_DEF
						  )
from dataclasses import dataclass, asdict, field, fields

# Default Values:
DEF: dict[str, str] = {
	"ka" : KA_DEF,
	"kv" : KV_DEF,
	"da" : DA_DEF,
	"b"  : B_DEF,
	"uid": UID_DEF,
	"sf" : SF_DEF
}
# Required Values:
REQ = {
	'seal': 'SEAL version', 
	'ka': 'Key Algorithm', 
	's': 'signature', 
	'd': 'domain name'
}

@dataclass(kw_only=True)
class SealBaseData:
	# Basic Seal datatype, describing the minimum data required to authenticate a signature (from a digest)
	# Required:
	seal: str = SEAL_DEF		# SEAL Version
	d:	  str					# Domain Name

	# Optional:  (with default values)
	ka:   KEY_ALGS_T  	= KA_DEF														# Key Algorithm
	kv:   SealKeyVersion= field(default_factory=lambda: SealKeyVersion(KV_DEF))			# Key Version
	uid:  SealUID		= field(default_factory=lambda: SealUID(UID_DEF))				# UUID/Date
	sf:   SealSignatureFormat = field(default_factory=lambda: SealSignatureFormat(SF_DEF)) # Signature Format
	#             (no default)
	id:   		Opt[str] = None								# Account identifier
	def __post_init__(self):
		if self.seal != SEAL_DEF: raise ValueError(f"Invalid SEAL version: \"{self.seal}\" ({type(self.seal).__name__}) != \"{SEAL_DEF}\" ({type(SEAL_DEF).__name__})")

	@classmethod
	def new(cls, 	d:   str,  					seal: Opt[str]= SEAL_DEF, 
		 			ka:   Opt[str] = KA_DEF,	kv:  Opt[str] = KV_DEF,		uid: Opt[str] = UID_DEF,	
					sf:	  Opt[str] = SF_DEF,	id:  Opt[str] = None):
		params = locals()
		del params["cls"]
		params = clean_p(params)
		return cls(**cls._load(**params))
	
	@classmethod
	def _load(cls,**params):
		# Try convert values from str -> relevant object
		ka = cls.ka_cast(params["ka"])
		if ka is None: raise ValueError("Invalid key algorithm: "+params["ka"])
		params["ka"] = ka

		params["kv"] = SealKeyVersion(params["kv"])
		
		params["uid"] = SealUID(params["uid"])
		params["sf"] = SealSignatureFormat(params["sf"])

		return params
	@classmethod
	def fromData(cls, data: Self, **params):
		data_dict = asdict(data)
		data_dict = filter_data(data_dict, cls)
		return cls(**data_dict)
	
	@classmethod
	def ka_cast(cls, ka: str) -> Opt[KEY_ALGS_T]:
		if ka in KEY_ALGS: return cast(KEY_ALGS_T, ka)
		return None
	
	def ka_key_size(self, private_key: SealBase64) -> int:
		return SealBaseData.ka_key_size_s(self.ka, private_key)
	def sig_size(self, private_key: SealBase64) -> int:
		return SealBaseData.sig_size_s(self.ka, self.sf, private_key)
	
	@classmethod
	def ka_key_size_s(cls, ka: KEY_ALGS_T, private_key: SealBase64) -> int:
		if ka == "rsa":
			return RSA.import_key(private_key.val).size_in_bits()
		raise RuntimeError("Invalid key algorithm: "+ka)
	@classmethod
	def sig_size_s(cls, ka: KEY_ALGS_T, sf: SealSignatureFormat, private_key: SealBase64) -> int:
		ka_b_size = cls.ka_key_size_s(ka, private_key)
		return sf.sig_len(ka_b_size)

	def toDict(self) -> dict[str, str]:
		attr_dict = asdict(self)
		str_dict : dict[str, str] = {}
		for key, value in attr_dict.items():
			if value is None: continue

			str_val = str(value)
			if len(str_val) == 0: continue
			if key in DEF and DEF[key] == str_val and not key in REQ: continue
			str_dict[key] = str_val
		return str_dict
	
	@classmethod
	def default(cls):
		return {k: v for k,v in DEF.items() if not(k in ["b", "da"])}
	
	def __str__(self) -> str:
		options = []
		attr_dict = self.toDict()
		
		attr_order = list(attr_dict.keys())
		
		attr_order.sort(key=lambda k: -1 if k == 'seal' else 99999 if k == 's' else len(str(attr_dict[k])))

		for attr in attr_order:
			str_val = format_str(attr_dict[attr])
			
			options.append(attr + "=" + str_val)
		return ' '.join(options)

@dataclass(kw_only=True)
class SealSignData(SealBaseData):
	# The minimum data required to sign an image (digest algorithm allows for double digest)
	da:   DA_ALGS_T	  	= DA_DEF				 # Digest Algorithm
	@classmethod
	def new(cls, 	d:   str,				 seal: Opt[str]= SEAL_DEF, 		ka:	 Opt[str] = KA_DEF,  
		 			kv:  Opt[str] = KV_DEF,  uid: Opt[str] = UID_DEF,		sf:	  Opt[str] = SF_DEF,
		 			id:  Opt[str] = None,  	 da:   Opt[str] = DA_DEF):
		params = locals()
		del params["cls"]
		params = clean_p(params)
		return cls(**cls._load(**params))
	@classmethod
	def _load(cls,**params):
		params = super()._load(**params)
		
		da = cls.da_cast(params["da"])
		if da is None: raise ValueError("Invalid digest algorithm: "+params["da"])
		params["da"] = da

		return params
	@classmethod
	def fromData(cls, data: SealBaseData, **params):
		# From SealBaseData:
		#		da: DA_ALGS_T = DA_DEF

		data_dict = asdict(data)

		da = cls.da_cast(params["da"])
		if da is None: raise ValueError("Invalid digest algorithm: "+params["da"])
		data_dict["da"] = da
		data_dict = filter_data(data_dict, cls)
		return cls(**data_dict)
	
	def ka_encrypt(self, private_key: SealBase64, hash_b: bytes) -> bytes:
		"""Use the key algorithm and private key to encrypt the digest

		Args:
			private_key (SealBase64)
			hash_b (bytes): Hash calculated using the `Cryto.Hash` package.

		Raises:
			RuntimeError: if the key algorithm isn't supported.
			ValueError: if the key is invalid.

		Returns:
			bytes: the encrypted digest"""
		
		hash = SealDigestInfo.dummy_hash(self.da, hash_b)

		if self.ka == "rsa":
			rsa_key = RSA.import_key(private_key.val)
			try:
				# Use a dummy hash (allows us to create a hash from hash_b (bytes))
				# pkcs1_15.__.sign(hash) only calls:
				#	 'hash.oid'   &   'hash.digest()'     which is implemented in DummyHash
				# See: https://github.com/Legrandin/pycryptodome/blob/master/lib/Crypto/Signature/pkcs1_15.py#L55
				return pkcs1_15.new(rsa_key).sign(hash)
			except ValueError:
				raise ValueError("Key is too short")
			except TypeError:
				raise ValueError("Key provided has no private component")
		raise RuntimeError("Invalid key algorithm: "+self.ka)

	
	def da_hash(self, file_bytes: bytes) -> bytes:
		return SealDigestInfo.hash_b(file_bytes, self.da).digest()
	
	@classmethod
	def da_cast(cls, da: str) -> Opt[DA_ALGS_T]:
		if da in DA_ALGS: return cast(DA_ALGS_T, da)
		return None
	@classmethod
	def default(cls):
		return {k: v for k,v in DEF.items() if not(k in ["b"])}

@dataclass(kw_only=True)
class SealSignData_(SealSignData):
	# Extended data for signing with optional textual information
	# Optional:   (no default)
	copyright: 	Opt[str] = None		# Copyright information
	info: 		Opt[str] = None		# Textual comment information
	sl:   		Opt[str] = None		# Signature Length (not implemented)	
	@classmethod
	def new(cls, 	d:   str,				 seal: Opt[str]= SEAL_DEF, 		ka:	 Opt[str] = KA_DEF,  
		 			kv:  Opt[str] = KV_DEF,  uid: Opt[str] = UID_DEF,		sf:	  Opt[str] = SF_DEF,
		 			id:  Opt[str] = None,  	 da:   Opt[str] = DA_DEF,
					
					copyright: Opt[str] = None,	info: 	Opt[str] = None,	sl:	 Opt[str] = None):
		params = locals()
		del params["cls"]
		params = clean_p(params)
		return cls(**cls._load(**params))
	@classmethod
	def _load(cls,**params):
		params = super()._load(**params)
		return params
	@classmethod
	def fromData(cls, data: SealBaseData, **params):
		# From SealBaseData:
		#		da: DA_ALGS_T = DA_DEF
		
		if not isinstance(data, SealSignData):
			data = SealSignData.fromData(data, **params)
		
		data_dict = asdict(data)
		data_dict = filter_data(data_dict, cls)
		return cls(**data_dict)
	
	@classmethod
	def da_cast(cls, da: str) -> Opt[DA_ALGS_T]:
		if da in DA_ALGS: return cast(DA_ALGS_T, da)
		return None

@dataclass(kw_only=True)
class SealSignData_F(SealSignData_):
	# Data for signing from within a file signing method. This includes the byte range which is used to generate a digest
	b:    SealByteRange = SealByteRange(B_DEF)	 # Digest Byte Range
	@classmethod
	def new(cls, 	d:   str,				 seal: Opt[str]= SEAL_DEF, 		ka:	 Opt[str] = KA_DEF,  
		 			kv:  Opt[str] = KV_DEF,  uid:  Opt[str] = UID_DEF,		sf:	  Opt[str] = SF_DEF,
		 			id:  Opt[str] = None,  	 da:   Opt[str] = DA_DEF,		copyright: Opt[str] = None,	
					info:Opt[str] = None, 	 sl:   Opt[str] = None,
					
					b: 	  str  = B_DEF):
		params = locals()
		del params["cls"]
		params = clean_p(params)
		return cls(**cls._load(**params))
	@classmethod
	def _load(cls,**params):
		params = super()._load(**params)

		params["b"] = SealByteRange(params["b"])

		return params
	@classmethod
	def fromData(cls, data: SealBaseData, **params):
		# From SealBaseData:
		#		da: DA_ALGS_T = DA_DEF
		#		 + byte_range
		# From SealSignData/SealSignData_:
		# 		byte_range: str|SealByteRange = B_DEF

		if not isinstance(data, SealSignData_):
			data = SealSignData_.fromData(data, **params)

		byte_range: str|SealByteRange = params["byte_range"] if "byte_range" in params else B_DEF

		data_dict = asdict(data)
		data_dict["b"] = byte_range if isinstance(byte_range, SealByteRange) else SealByteRange(byte_range)
		data_dict = filter_data(data_dict, cls)
		return cls(**data_dict)
	@classmethod
	def default(cls):
		return DEF

@dataclass(kw_only=True)
class SealMetadata(SealSignData_F):
	# Full metadata which can be saved into the file
	s:    SealSignature   	 		# Signature	
	
	@classmethod
	def new(cls, 	d:   str,				 seal: Opt[str]= SEAL_DEF, 		ka:	 Opt[str] = KA_DEF,  
		 			kv:  Opt[str] = KV_DEF,  uid:  Opt[str] = UID_DEF,		sf:	  Opt[str] = SF_DEF,
		 			id:  Opt[str] = None,  	 da:   Opt[str] = DA_DEF,		copyright: Opt[str] = None,	
					info:Opt[str] = None, 	 sl:   Opt[str] = None,
					
					b: 	  str  = B_DEF, 	s: str=""):
		params = locals()
		del params["cls"]
		params = clean_p(params)
		return cls(**cls._load(**params))

	@classmethod
	def _load(cls, **params):
		params = super()._load(**params)
		params["s"] = SealSignature.fromStr(params["s"], params["sf"])

		return params	

	@classmethod
	def fromData(cls, data: SealBaseData, **params) -> Self:
		# From SealBaseData:
		#		da: DA_ALGS_T = DA_DEF
		#		+ byte_range + sig + sig_date
		# From SealSignData/SealSignData_:
		#		byte_range: str|SealByteRange = B_DEF
		#		+ sig + sig_date
		# From SealSignData_F:
		#		sig: 		str|SealSignature
		#		or:
		#		sig:		bytes
		# 		sig_date    Opt[datetime]     = None
		if not isinstance(data, SealSignData_F):
			data = SealSignData_F.fromData(data, **params)
		
		data_dict = asdict(data)
		data_dict["s"] = sig_from_params(data_dict["sf"], **params)

		return cls(**data_dict)

	@classmethod
	def fromWrapper(cls, wrap_str: str) -> Self:
		if not re.match("^<seal (.)*/>", wrap_str):
			raise ValueError(f"Not a valid SEAL wrapper. Must be be of the form: <seal .../>")
		seal_str = wrap_str[6:-2]
		return cls.fromEntry(seal_str)

	@classmethod
	def fromEntry(cls, meta_str: str) -> Self:
		meta_dict : dict[str, Any] = {}
		meta_struct = get_type_hints(cls)
		fields = get_fields(meta_str)

		for field in fields:
			[key, val] = field
			if not key in meta_struct:
				raise ValueError(f"Unexpected key in SEAL string: \'{key}\'")
			value = clean_str(val)

			meta_dict[key] = value
		
		# Check Required:
		for key in REQ:
			if not key in meta_dict: raise ValueError(f"Missing {REQ[key]} from: {meta_str}")
		return cls.new(**meta_dict)
	
	def toEntry(self) -> str:
		return self.__str__()
	
	def toWrapper(self) -> str:
		return f"<seal {self.toEntry()}/>"
	

@dataclass(kw_only=True)	
class SealVerifyData(SealSignData):
	# Required:
	s:	  SealSignature			# Signature

	@classmethod
	def new(cls, 	d:   str,				 seal: Opt[str]= SEAL_DEF, 		ka:	 Opt[str] = KA_DEF,  
		 			kv:  Opt[str] = KV_DEF,  uid: Opt[str] = UID_DEF,		sf:	  Opt[str] = SF_DEF,
		 			id:  Opt[str] = None,  	 da:   Opt[str] = DA_DEF, 		s: str = ""):
		params = locals()
		del params["cls"]
		params = clean_p(params)
		return cls(**cls._load(**params))
	
	@classmethod
	def _load(cls,**params):
		params = super()._load(**params)
		params["s"] = SealSignature.fromStr(params["s"], params["sf"])

		return params
	@classmethod
	def fromData(cls, data: SealMetadata|SealBaseData, **params):
		# From SealBaseData:
		# 		da			DA_ALGS_T = DA_DEF
		#		+ sig/sig_date
		# From SealSignData:
		#		sig: 		str|SealSignature
		#		or:
		#		sig:		bytes
		# 		sig_date    Opt[datetime]     = None
		# 
		# From SealMetadata: Nothing
		data_dict = asdict(data)

		if isinstance(data, SealBaseData) and not (isinstance(data, (SealMetadata, SealVerifyData))):
			data_dict["s"] = sig_from_params(data_dict["sf"], **params)

		# f_names = [f.name for f in fields(cls)]
		# data_dict = {k:v for k,v in data_dict.items() if k in f_names}
		data_dict = filter_data(data_dict, cls)

		return cls(**data_dict)

	def ka_verify(self, public_key: SealBase64, hash_b: bytes) -> bool:
		"""Use the key algorithm to verify the encrypted digest matches the signature

		Args:
			public_key (SealBase64)
			hash_b (bytes): Hash calculated using the `Crypt.Hash` package.

		Raises:
			RuntimeError: if the key algorithm or signature is invalid

		Returns:
			bool: True = encrypted digest matches the signature"""
		if self.s is None: raise RuntimeError("No signature set")
		if self.ka == "rsa":
			rsa_key = RSA.import_key(public_key.val)
			hash = SealDigestInfo.dummy_hash(self.da, hash_b)
			try:
				# Use a dummy hash (allows us to create a hash from hash_b (bytes))
				# pkcs1_15.__.verify(hash, signature) only calls:
				#		'hash.oid'  &  'hash.digest()'  which is implemented in DummyHash
				# See: https://github.com/Legrandin/pycryptodome/blob/master/lib/Crypto/Signature/pkcs1_15.py#L87
				pkcs1_15.new(rsa_key).verify(hash, self.s.sig_b)
				return True
			except (ValueError, TypeError):
				return False
		raise RuntimeError("Invalid key algorithm: "+self.ka)

def sig_from_params(sf: SealSignatureFormat, **params) -> SealSignature:
	if not "sig" in params:
		raise ValueError("Missing signature")
	sig: str|bytes          = params["sig"]
	sig_date: Opt[datetime] = params["sig_date"] if "sig_date" in params and isinstance(params["sig_date"], datetime) else None

	if isinstance(sig, SealSignature):
		return sig
	elif isinstance(sig, bytes):
		return SealSignature(sig, sf, sig_date)
	else:
		return SealSignature.fromStr(str(sig), sf)

def clean_p(params: dict[str, Any]):
	new_params = {}
	for k,v in params.items():
		if v is not None:
			new_params[k] = v
		elif k in DEF:
			new_params[k] = DEF[k]
	return new_params

def filter_data(data_dict: dict[str, Any], target_type: type):
	# Filter the data_dict to remove any parameters not used for the target_type
	field_names = [f.name for f in fields(target_type)]
	return {k:v for k,v in data_dict.items() if k in field_names}