import urllib.request,  urllib.error
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Union
import json

from .seal_models import SealBase64, SealSignature
from .seal_meta import SealSignData
	
class SealSigner(ABC):
	@abstractmethod
	def sign(self, s_data: SealSignData, digest_hash: bytes) -> SealSignature:
		"""Signs the digest

		Args:
			s_meta (SealMetadata): Metadata object to be signed
			digest_hash (Hash): Hash of file digest

		Returns:
			SealSignature: Signed obj
		"""
		pass

	@abstractmethod
	def signature_size(self, s_data: SealSignData) -> int:
		"""Returns the size of the generated signature (excluding the date)

		Args:
			s_meta (SealMetadata): Metadata which will accompany the signature

		Returns:
			int: Size of the signature (number of bits)
		Throws:
			ValueError if invalid parameters passed
			RuntimeException if something unexpected went wrong
		"""
		pass
	@abstractmethod
	def type_str(self) -> str:
		"""Returns the type of the signer as a string"""
		pass

class SealLocalSign(SealSigner):
	private_key: SealBase64

	def __init__(self, private_key: Union[str, bytes]):
		self.private_key = SealBase64(private_key)
	
	def sign(self, s_data: SealSignData, digest_hash: bytes) -> SealSignature:
		sig_d = None

		if (s_data.sf.date_format is not None) or (s_data.id is not None):
			# Double digest
			digest1 = digest_hash
			head = ""
			if s_data.id is not None:
				head = s_data.id + ":" + head
			if s_data.sf.date_format is not None:
				sig_d = datetime.now()
				head = s_data.sf.format_date(sig_d) + ":" + head
			digest2 = head.encode() + digest1
			digest_hash = s_data.da_hash(digest2)
		sig_b = s_data.ka_encrypt(self.private_key, digest_hash)
		return SealSignature(sig_b, s_data.sf, sig_d)
		
	def signature_size(self, s_data: SealSignData):
		return s_data.ka_key_size(self.private_key)

	def type_str(self) -> str:
		return "Local"

class SealDummySign(SealSigner):
	size: int
	def __init__(self, sig_size: int):
		self.size = sig_size
	
	def sign(self, s_data: SealSignData, digest_hash: bytes) -> SealSignature:
		size = self.size // 8
		date = None
		if (s_data.sf.date_format is not None): 
			date = datetime.now()

		return SealSignature(bytes(size), s_data.sf, date)
	
	def signature_size(self, s_data: SealSignData):
		return self.size

	def type_str(self) -> str:
		return "Dummy"


# For https://signmydata.com:
class SealRemoteSign(SealSigner):
	api_url: str
	api_key: str

	def __init__(self, api_url: str, api_key: str):
		self.api_url = api_url
		self.api_key = api_key
		
		
	def sign(self, s_data: SealSignData, digest_hash: bytes) -> SealSignature:
		digest_h: str = digest_hash.hex()
		req_data = {
			'seal':  str(s_data.seal),
			'apikey': self.api_key,
			'ka': str(s_data.ka),
			'kv': str(s_data.kv),
			'sf': str(s_data.sf),
			'digest': digest_h
		}
		if s_data.id is not None:
			req_data['id'] = s_data.id

		try:
			sign_resp = self._send_req_dict(req_data, self.api_url)
			if 'error' in sign_resp:			raise ValueError("Error: "+sign_resp["error"])
			if not 'signature'  in sign_resp: 	raise ValueError("Missing signature")
		except ValueError as e:               	raise ValueError(f"Unable to sign digest using {self.api_url}\n    Data: {req_data}\n    {str(e)}") from None

		return SealSignature.fromStr(sign_resp['signature'], s_data.sf)
	
	def signature_size(self, s_data: SealSignData) -> int:
		req_data = {
			'seal': str(s_data.seal),
			'apikey': self.api_key,
			'kv': str(s_data.kv),
			'ka': str(s_data.ka),
			'sf': "hex",
		}
		if s_data.id is not None:
			req_data['id'] = s_data.id

		sign_params = self._send_req_dict(req_data, self.api_url)
		if 'error' in sign_params:
			raise ValueError(f"Unable to fetch signing parameters using {self.api_url}\n    Data: {req_data}\n    "+sign_params['error'])
		if not 'sigsize' in sign_params:
			raise ValueError(f"Unable to fetch signing parameters using {self.api_url}\n    Data: {req_data}\n    Missing sigsize")

		size = sign_params['sigsize']*4

		if size.isnumeric():
			return int(size)
		return 0
	
	def type_str(self) -> str:
		return "Remote"

	@staticmethod
	def _send_req_dict(data_dict: dict[str, str], url: str, headers:dict[str, str]={}) -> dict[str, str]:
		"""Sends the data in a request to the api_url, returning the results as a string dictionary

		Args:
			data_dict (dict[str, str]): Input data dictionary, sent in the form: k1=v1&k2=v2...

		Raises:
			ValueError: Error when requesting data from the url
			SyntaxError: Unable to parse data as JSON

		Returns:
			dict[str, str]"""
		data_b = '&'.join([f'{k}={v}' for k, v in data_dict.items()]).encode()
		
		if headers: req_h = headers
		else:		req_h = {
								'content-type': 'application/x-www-form-urlencoded',
								'accept': '*/*',
								'User-Agent': 'Wget/1.21.1',
								}
		req = urllib.request.Request(url, data_b,
                            headers=req_h)
		try:
			response = urllib.request.urlopen(req)
		except urllib.error.HTTPError as e:
			raise ValueError(f"HTTPError: {e.code}")
		except urllib.error.URLError as e:
			raise ValueError(f"URLError:  {e.reason}")
		
		response_b : bytes = response.read()
		try:	
			return json.loads(response_b)
		except json.decoder.JSONDecodeError:
			raise SyntaxError("Invalid JSON: "+response_b.decode('utf8'))