from seal_python import *
import pytest


def convert_dict(test_dict):
    test_arr = []
    for k,v in test_dict.items():
        for i,arr in enumerate(v):
            for item in arr:
                test_arr.append((k, item, i%2==0))
    return test_arr

# Testing multiple models
model_tests = {
    SealByteRange: (
        ["F~S,s~f","F+4~S,s~f-20","F~S,s+4~f","F~S-2,S-2~S,s~f","~S,s~", "p~S"], 
        ["F~S,S~f","F~S-4,S-5~S,s~f","F~S,s~F", "F~f"]),
    SealSignatureFormat: (
        ["hex", "HEX", "base64", "bin", "date:hex", "date3:bin", "date0:HEX", "date9:hex"],
        ["BIN", "date:", "date3", "TEXT:date0"]),
    SealKeyVersion: (["1", "AZax03", "test++key.", ], ["test key", "Test_"]),
    SealUID: (["", "identifier"], ["test key", "\"test\""]),
    SealBase64: (
        ["abcdefg", "abcdefg=", "\"abcdefg\"", "\"abC\" \"defg\"", "\"kEyy\""],
        ["key_", "\'testkey"]
    )
}

@pytest.mark.parametrize(["model", "input", "is_valid"], convert_dict(model_tests))
def test_models(model, input: str, is_valid: bool):
    try:
        model(input)
        assert is_valid, f"Expecting an exception"
    except ValueError as e:
        assert not is_valid, f"{e}"


# Testing SealSignatureFormat
sig_tests = {
    "bin": (
        ["1010110110100001100"],                # Valid
        ["Test", "00 ", "015", "11101_101"]),   # Invalid  etc
    "hex": (
        ["0123456789abcdef"],
        ["12AB", "c2-4f", "0efg"]),
    "HEX": (
        ["0123456789ABCDEF"], 
        ["12ab", "AC-3D", "0EFG"]),
    "base64": (
        ["dGVzdGluZw==", "aGVsbG9vbw", "aGk   "], 
        ["dCB!", "eW 8="]),
    "date:bin": (
        ["20241123174403:00110001"],
        ["20241123174403.01:01111000", "20241323174403:01100011", "YYYYMMDDhhmmss:10100011"],
    )
}

@pytest.mark.parametrize(["sf_str", "s", "is_valid"], convert_dict(sig_tests))
def test_signature(sf_str: str, s: str, is_valid: bool):
    try:
        sf = SealSignatureFormat(sf_str)
        SealSignature.fromStr(s, sf)
        assert is_valid, f"Expecting an exception"
    except ValueError as e:
        assert not is_valid, f"{e}"


# Testing SealDigestInfo
di_tests = [
    # hex/HEX/base64/bin  sha256/sha512/sha1    hash_s                                                       is_valid hash_valid
    (     "hex",              "sha256",    "124db2f794301d895f5c0fcb5b545e3740c49d52d91ed48a3cc3fc9a157ef925",  True,    True   )
]


# @pytest.mark.parametrize(["df", "da", "hash_s", "is_valid", "hash_valid"], di_tests)
# def test_digestinfo(df: str, da: str, hash_s: str, is_valid: bool, hash_valid: bool):
#     try:
#         di = SealDigestInfo(df, da)
#     except ValueError as e:
#         assert not is_valid, f"{e}"
#         return
#     if not is_valid:
#         assert False, "Accepted invalid digest info"
    
#     try:
#         hash = di.hashFromStr(hash_s)
#         hash_s2 = di.hashToStr(hash)
#         hash2 = di.hashFromStr(hash_s2)
#         assert hash == hash_s2, f"Hashes not matching  {hash.digest()!r} ({hash_s}) != {hash2.digest()!r} ({hash_s2})"
#     except ValueError as e:
#         assert not hash_valid, f"{e}"
#         return
    