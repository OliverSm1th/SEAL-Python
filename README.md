# SEAL-Python
[Secure Evidence Attribution Label (SEAL)](https://github.com/hackerfactor/SEAL) allows users to assign attribution with authentication to media.

This is an (incomplete*) implementation of SEAL in Python according to [Version 1.1.4](https://github.com/hackerfactor/SEAL/blob/d05d7b6e81a025cd1b00919549e1a013115ec134/SPECIFICATION.md).

---

****Important Note:** The implementation currently only works for signing and verifying <u>PNG</u> files using the rsa key algorithm

  <br><br>

## Basic Usage
### Reading SEAL records from a PNG file
```python
with SealFile("seal.png") as s:
    result: list[SealEntry] = seal_read_png(s)
print(result)
```
### Writing SEAL record to a PNG file
```python
s_data = SealSignData_(d="[domain]", copyright="...", info="...", ka="rsa")
# Local Signing:
s_sign = SealLocalSign(private_key="...")
# Remote Signing:
s_sign = SealRemoteSign(api_url="https://signmydata.com/?sign", api_key="...")

with SealFile("seal.png") as s:
    seal_sign_png(s, s_data, s_sign, new_path="signed_seal.png")
```