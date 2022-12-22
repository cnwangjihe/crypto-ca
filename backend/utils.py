from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from base64 import b64decode, b64encode

PEM_PRIVKEY_HEADER = "-----BEGIN PRIVATE KEY-----"
PEM_PRIVKEY_FOOTER = "-----END PRIVATE KEY-----"

class AppException(Exception):
    pass


def load_ECDSA_pubkey(pubkey: str) -> ec.EllipticCurvePublicKey:
    try:
        user_pubkey = serialization.load_pem_public_key(pubkey.encode())
    except ValueError:
        raise AppException("pubkey load failed.")

    if not isinstance(user_pubkey, ec.EllipticCurvePublicKey):
        raise AppException("pubkey should be ECDSA.")
    return user_pubkey

def xor_ECDSA_privkey(privkey: str, passwd: str) -> str:
    st = privkey.find(PEM_PRIVKEY_HEADER) + len(PEM_PRIVKEY_HEADER)
    ed = privkey.find(PEM_PRIVKEY_FOOTER)
    encrypted = b64decode(privkey[st:ed])
    xor_key = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = len(encrypted),
        salt = b"\x8doSl\x13h\x15B2\x16\x8d.\xac-O\x96",
        iterations = 1926,
    ).derive(passwd.encode())
    decrypted = b64encode(bytes(a ^ b for (a, b) in zip(encrypted, xor_key))).decode()
    decrypted = '\n'.join(decrypted[i:i+64] for i in range(0, len(decrypted), 64))
    return f"{PEM_PRIVKEY_HEADER}\n{decrypted}\n{PEM_PRIVKEY_FOOTER}"

def load_ECDSA_privkey(privkey: str) -> ec.EllipticCurvePrivateKey:
    try:
        user_privkey = serialization.load_pem_private_key(privkey.encode(), None)
    except ValueError:
        raise AppException("privkey load failed.")

    if not isinstance(user_privkey, ec.EllipticCurvePrivateKey):
        raise AppException("privkey should be ECDSA.")
    return user_privkey