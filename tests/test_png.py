from seal_python import *
import pytest
from dotenv import dotenv_values
SECRETS = dotenv_values()

read_files: list[tuple[str, bool]] = [
    ("./tests/seal-sign.png", True)
]

@pytest.mark.parametrize(["file_path", "is_valid"], read_files)
def test_png_read(file_path: str, is_valid: bool):
    try:
        with SealFile(file_path, True) as s:
            arr = seal_read_png(s)
            if len(arr) != 1: raise ValueError(f"Returned {len(arr)} seal entries")
        assert is_valid, f"Expecting not valid"
    except ValueError as e:
        assert not is_valid, f"{e}"

sign_files: list[tuple[str, SealSignData, SealSigner]] = [
    (
        "./tests/seal.png",
        SealSignData_.new(
            d=SECRETS["TEST_LOCAL_D"] or "",
            ka="rsa", info="Signed as part of the SEAL-Python testing", sf="date:base64"), 
        SealLocalSign(
            private_key=SECRETS["TEST_LOCAL_KEY"] or "")),
    (
        "./tests/seal.png",
        SealSignData_.new(
            d=SECRETS["TEST_REMOTE_D"] or "", 
            id=SECRETS["TEST_REMOTE_ID"] or "",
            sf="date:base64"), 
        SealRemoteSign(
            api_url=SECRETS["TEST_REMOTE_API"] or "", 
            api_key=SECRETS["TEST_REMOTE_API_KEY"] or ""))
]

@pytest.mark.parametrize(["file_path", "s_data", "signer"], sign_files)
def test_png_sign(file_path: str, s_data: SealSignData_, signer: SealSigner):
    try:
        with SealFile(file_path, True) as s:
            seal_sign_png(s, s_data, signer, file_path[:-4]+"-test.png")
            arr = seal_read_png(s)
            if len(arr) != 1: raise ValueError(f"Returned {len(arr)} valid seal entries")
            assert str(SealSignData_.fromData(arr[0].seal)) == str(s_data)
    except ValueError as e:
        assert False, f"{e}"