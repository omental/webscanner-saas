import base64
import hashlib
import hmac
import os
import secrets


class EncryptionKeyMissingError(RuntimeError):
    pass


def _get_key() -> bytes:
    key = os.environ.get("ENCRYPTION_KEY")
    if not key:
        raise EncryptionKeyMissingError(
            "ENCRYPTION_KEY is required to save payment method secrets."
        )
    return key.encode("utf-8")


def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    output = bytearray()
    counter = 0
    while len(output) < length:
        output.extend(
            hmac.new(
                key,
                nonce + counter.to_bytes(4, "big"),
                hashlib.sha256,
            ).digest()
        )
        counter += 1
    return bytes(output[:length])


def encrypt_secret(value: str) -> str:
    key = _get_key()
    nonce = secrets.token_bytes(16)
    plaintext = value.encode("utf-8")
    stream = _keystream(key, nonce, len(plaintext))
    ciphertext = bytes(left ^ right for left, right in zip(plaintext, stream))
    signature = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()
    token = base64.urlsafe_b64encode(nonce + signature + ciphertext).decode("ascii")
    return f"v1:{token}"
