from typing      import   Optional as Opt, Any, cast, get_type_hints
from .seal_models import  (SealKeyVersion, SealUID, SealBase64, SealTimestamp,
						  KEY_ALGS_T, KEY_ALGS, get_fields, clean_str)



class SealDNS():
	# Required:
	seal: 	str					# SEAL Version
	p:		Opt[SealBase64]		# Base64 Public Key  (None=revoke)
	ka:   	KEY_ALGS_T			# Key Algorithm
	
	# Optional: (with default values)
	kv:		SealKeyVersion		# Key Version
	uid: 	SealUID				# UUID/Date
	#			(no default)
	r:		Opt[SealTimestamp]	# Revocation Date (in GMT)

	def __init__(self,  seal: str,	p: Opt[str],	ka: str = 'rsa',  
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
		
		self.r = SealTimestamp(r) if r is not None else None  # All signatures after the date is invalid

	@classmethod
	def fromEntry(cls, dns_str: str):
		dns_dict : dict[str, Any] = {}
		dns_struct = get_type_hints(cls)
		fields = get_fields(dns_str)

		for field in fields:
			[key, val] = field
			if not key in dns_struct:
				raise ValueError("Unexpected key in DNS string: "+key)
			value = clean_str(val)
			
			# if key == 'seal': 	
			# 	if not value.isnumeric():
			# 		raise ValueError(f"Invalid integer value for \'{key}\' in SEAL string: \'{value}\'")
			# 	else:
			# 		dns_dict[key] = int(value)
			dns_dict[key] = value

		required = {'seal': 'SEAL version', 'ka': 'Key Algorithm'}
		
		for key in required:
			if not key in dns_dict: raise ValueError(f"Missing {dns_dict[key]} ({key})")

		return cls(**dns_dict)

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