from datetime import datetime
import json
from .seal_meta import SealMetadata
from abc import ABC, abstractmethod
import urllib.request,  urllib.error

from .seal_models import SealBase64, SealSignature, SealSignatureFormat
	
class SealSigner(ABC):
	@abstractmethod
	def sign(self, s_meta: SealMetadata, digest_b: bytes) -> SealMetadata:
		"""Signs the digest

		Args:
			s_meta (SealMetadata): Metadata object to be signed
			digest (Hash): Calculated file digest

		Returns:
			SealMetadata: Signed obj
		"""
		pass

	@abstractmethod
	def signature_size(self, s_meta: SealMetadata) -> int:
		"""Returns the size of the generated signature (excluding the date)

		Args:
			s_meta (SealMetadata): Metadata which will accompany the signature

		Returns:
			int: Size of the signature (number of bits)
		"""
		pass
	@abstractmethod
	def type_str(self) -> str:
		"""Returns the type of the signer as a string"""
		pass

class SealLocalSign(SealSigner):
	private_key: SealBase64

	def __init__(self, private_key: str|bytes):
		self.private_key = SealBase64(private_key)
	
	def sign(self, s_meta: SealMetadata, digest_b: bytes) -> SealMetadata:
		digest_hash = s_meta.da_hash(digest_b)
		date = None

		if (s_meta.sf.date_format is not None) or (s_meta.id is not None):
			# Double digest
			digest1 = digest_hash.digest()
			head = ""
			if s_meta.id is not None:
				head = s_meta.id + ":" + head
			if s_meta.sf.date_format is not None:
				date = datetime.now()
				head = s_meta.sf.format_date(date) + ":" + head
			digest2 = head.encode() + digest1
			digest_hash = digest_hash.new(digest2)
		signature = s_meta.ka_encrypt(self.private_key, digest_hash)
		s_meta.set_signature(signature, date)
		return s_meta
		
	def signature_size(self, s_meta: SealMetadata):
		return s_meta.ka_key_size(self.private_key)
		# print("sig size: "+str(size))
		# if (s_meta.sf.date_format is None or s_meta.sf.date_len() <= 0): 
		# 	print("no date")
		# 	return size
		# else:
		# 	print("date size: "+str(s_meta.sf.date_len()))
		# 	return size + ((s_meta.sf.date_len() + 1)*4)
	def type_str(self):
		return "Local"

class SealDummySign(SealSigner):
	size: int
	def __init__(self, sig_size: int):
		self.size = sig_size
	
	def sign(self, s_meta: SealMetadata, _: bytes) -> SealMetadata:
		size = self.size // 8
		print(f"DUMMY (size={size})")
		date = None
		if (s_meta.sf.date_format is not None): 
			date = datetime.now()
		# sig = SealSignature(SealSignatureFormat("hex"), bytes(size))
		# s_meta.s = sig
		s_meta.set_signature(bytes(size), date)
		return s_meta
	
	def signature_size(self, _: SealMetadata):
		return self.size

	def type_str(self):
		return "Dummy"


# For https://signmydata.com:
class SealRemoteSign(SealSigner):
	api_url: str
	api_key: str

	def __init__(self, api_url: str, api_key: str):
		self.api_url = api_url
		self.api_key = api_key
		
		
	def sign(self, s_meta: SealMetadata, digest_b: bytes) -> SealMetadata:
		digest = s_meta.da_hash(digest_b)

		digest_h = digest.digest().hex()
		req_data = {
			'seal':  str(s_meta.seal),
			'apikey': self.api_key,
			'ka': str(s_meta.ka),
			'kv': str(s_meta.kv),
			'sf': str(s_meta.sf),
			'digest': digest_h
		}
		if s_meta.id is not None:
			req_data['id'] = s_meta.id

		try:
			sign_resp = self._send_req_dict(req_data, self.api_url)
			if 'error' in sign_resp:			raise ValueError("Error: "+sign_resp["error"])
			if not 'signature'  in sign_resp: 	raise ValueError("Missing signature")
		except ValueError as e:               	raise ValueError(f"Unable to sign digest using {self.api_url}\n    Data: {req_data}\n    {str(e)}") from None
		print(sign_resp['signature'])
		print(sign_resp['sigsize'])
		sig = SealSignature.fromStr(s_meta.sf, sign_resp['signature'])
		s_meta.s = sig
		
		return s_meta
	
	def signature_size(self, s_meta: SealMetadata):
		req_data = {
			'seal': str(s_meta.seal),
			'id': s_meta.id,
			'apikey': self.api_key,
			'kv': str(s_meta.kv),
			'ka': str(s_meta.ka),
			'sf': "hex",
		}

		sign_params = self._send_req_dict(req_data, self.api_url)
		if 'error' in sign_params:
			raise ValueError(f"Unable to fetch signing parameters using {self.api_url}\n    Data: {req_data}\n    "+sign_params['error'])
		if not 'sigsize' in sign_params:
			raise ValueError(f"Unable to fetch signing parameters using {self.api_url}\n    Data: {req_data}\n    Missing sigsize")

		size = sign_params['sigsize']*4
		# TODO check this works
		# if (s_meta.sf.date_format is not None and s_meta.sf.date_len() > 0):
		# 	size -= (s_meta.sf.date_len() + 1)
		print(size)
		return size
	
	def type_str(self):
		return "Remote"

	@staticmethod
	def _send_req_dict(data_dict: dict[str, str], url: str) -> dict[str, str]:
		"""Sends the data in a request to the api_url, returning the results as a string dictionary

		Args:
			data_dict (dict[str, str]): Input data dictionary, sent in the form: k1=v1&k2=v2...

		Raises:
			ValueError: Error when requesting data from the url
			SyntaxError: Unable to parse data as JSON

		Returns:
			dict[str, str]  """
		data_b = '&'.join([f'{k}={v}' for k, v in data_dict.items()]).encode()
		req = urllib.request.Request(url, data_b,
                            headers={
								'content-type': 'application/x-www-form-urlencoded',
								'accept': '*/*',
								'User-Agent': 'Wget/1.21.1',
								})
		try:
			response = urllib.request.urlopen(req)
		except urllib.error.URLError as e:
			raise ValueError("URLError:  "+e.reason)
		except urllib.error.HTTPError as e:
			raise ValueError("HTTPError: "+e.code)
		response_b : bytes = response.read()
		try:	
			return json.loads(response_b)
		except json.decoder.JSONDecoderError:
			raise SyntaxError("Invalid JSON: "+response_b.decode('utf8'))