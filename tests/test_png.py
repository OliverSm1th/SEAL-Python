from seal_python import *
import pytest

files: list[tuple[str, bool]] = [
    ("./tests/seal-sign.png", True)
]


@pytest.mark.parametrize(["file_path", "is_valid"], files)
def test_files(file_path: str, is_valid: bool):
    try:
        with SealFile(file_path, True) as s:
            arr = seal_read_png(s)
            if len(arr) != 1: raise ValueError(f"Returned {len(arr)} seal entries")
        assert is_valid, f"Expecting not valid"
    except ValueError as e:
        assert not is_valid, f"{e}"