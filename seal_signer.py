from datetime import datetime
from typing import NamedTuple
from seal_meta import Hash, SealMetadata
from abc import ABC, abstractmethod
import urllib.request, urllib.parse

from seal_models import SealBase64
	
class SealSigner(ABC):
	def sign(self, s_meta: SealMetadata, digest_b: bytes) -> SealMetadata:
		digest_hash = s_meta.da_hash(digest_b)

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
		signature = self._generate_signature(s_meta, digest_hash)
		s_meta.set_signature(signature, date)
		return s_meta

	@abstractmethod
	def _generate_signature(self, s_meta: SealMetadata, last_digest: Hash) -> bytes:
		pass

class SealLocalSign(SealSigner):
	private_key: SealBase64
	def __init__(self, private_key: str|bytes):
		self.private_key = SealBase64(private_key)
	
	def _generate_signature(self, s_meta: SealMetadata, last_digest: Hash) -> bytes:
		return s_meta.ka_encrypt(self.private_key, last_digest)
	
class SealRemoteSign(SealSigner):
	api_url: str
	api_key: str

	def __init__(self, api_url: str, api_key: str):
		self.api_url = api_url
		self.api_key = api_key
		
		
	def _generate_signature(self, s_meta: SealMetadata, last_digest: Hash) -> bytes:
		data_dict = s_meta.toDict()
		data_dict['apikey'] = self.api_key
		data_dict['digest'] = last_digest.digest().hex()
		del data_dict['d']
		# data = json.dumps(data_dict).encode()
		data = urllib.parse.urlencode(data_dict).encode()
		req = urllib.request.Request(self.api_url, data,
                            headers={
								'content-type': 'application/x-www-form-urlencoded',
								'accept': '*/*',
								'connection': 'keep-alive'
								})
		response = urllib.request.urlopen(req)
		print(response.read().decode('utf8'))
		return bytes()