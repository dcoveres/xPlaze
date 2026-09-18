import secrets
import hashlib
import hmac
import os
from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicNumbers, SECP256K1
from cryptography.exceptions import InvalidSignature

#xPlaze — symmetric encryption
# Параметры кривой secp256k1 (для справки)
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
A = 0
B = 7
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

#Номер версии
xPlze = 5

class Point:
    __slots__ = ('x', 'y')
    def __init__(self, x, y):
        self.x = x % P
        self.y = y % P

def is_valid_point(p: Point) -> bool:
    if p is None:
        return False
    # Проверка уравнения y^2 = x^3 + 7 (mod P)
    if (p.y * p.y - (p.x * p.x * p.x + 7)) % P != 0:
        return False
    # Точка бесконечности (0,0) недопустима
    if p.x == 0 and p.y == 0:
        return False
    return True

def _point_to_public_key(p: Point):
    if not is_valid_point(p):
        raise ValueError("Невалидная точка")
    public_numbers = EllipticCurvePublicNumbers(p.x, p.y, SECP256K1())
    return public_numbers.public_key(default_backend())

def _public_key_to_point(pub_key):
    numbers = pub_key.public_numbers()
    return Point(numbers.x, numbers.y)

def _ecdh_multiply(private_scalar: int, point: Point) -> Point:
    private_key = ec.derive_private_key(private_scalar, SECP256K1(), default_backend())
    pub_key = _point_to_public_key(point)
    shared_secret = private_key.exchange(ec.ECDH(), pub_key)
    x = int.from_bytes(shared_secret, 'big')
    return Point(x, 0)  
    
def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()

def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    output = b""
    counter = 1
    while len(output) < length:
        h = hmac.new(prk, output[-32:] + info + bytes([counter]), hashlib.sha256)
        output += h.digest()
        counter += 1
    return output[:length]

def _derive_keys(shared_secret: bytes, salt: bytes, info: bytes) -> Tuple[bytes, bytes]:
    prk = _hkdf_extract(salt, shared_secret)
    okm = _hkdf_expand(prk, info, 64)
    return okm[:32], okm[32:]

def _xor_stream(key: bytes, nonce: bytes, length: int) -> bytes:
    stream = b""
    ctr = 1
    while len(stream) < length:
        h = hmac.new(key, nonce + ctr.to_bytes(4, 'big'), hashlib.sha256)
        stream += h.digest()
        ctr += 1
    return stream[:length]

def encrypt(msg: bytes, private_key: int) -> bytes:
    if not (1 < private_key < N):
        raise ValueError("Private key вне допустимого диапазона")
    if not msg:
        raise ValueError("Сообщение не может быть пустым")

    k = secrets.randbelow(N - 1) + 1
    G_point = Point(GX, GY)
    iv_point = _ecdh_multiply(k, G_point)  
    ephemeral_private = ec.derive_private_key(k, SECP256K1(), default_backend())
    ephemeral_public = ephemeral_private.public_key()
    iv = _public_key_to_point(ephemeral_public) 
    shared_point = _ecdh_multiply(private_key, iv)
    shared_secret = shared_point.x.to_bytes(32, 'big') 

    salt = iv.x.to_bytes(32, 'big') + iv.y.to_bytes(32, 'big')
    info = b"EC-Stream-Cipher v1"
    enc_key, mac_key = _derive_keys(shared_secret, salt, info)

    nonce = os.urandom(16)
    gamma = _xor_stream(enc_key, nonce, len(msg))
    ciphertext = bytes([msg[i] ^ gamma[i] for i in range(len(msg))])

    mac = hmac.new(mac_key,
                   iv.x.to_bytes(32, 'big') + iv.y.to_bytes(32, 'big') + nonce + ciphertext,
                   hashlib.sha256).digest()

    return iv.x.to_bytes(32, 'big') + iv.y.to_bytes(32, 'big') + nonce + ciphertext + mac

def decrypt(blob: bytes, private_key: int) -> bytes:
    if not (1 < private_key < N):
        raise ValueError("Private key вне допустимого диапазона")
    if len(blob) < 64 + 16 + 32:
        raise ValueError("Blob слишком короткий")

    ivx = int.from_bytes(blob[:32], 'big')
    ivy = int.from_bytes(blob[32:64], 'big')
    if not (0 <= ivx < P and 0 <= ivy < P):
        raise ValueError("Координаты IV вне допустимого диапазона")

    iv = Point(ivx, ivy)
    if not is_valid_point(iv):
        raise ValueError("Невалидная точка IV")

    nonce = blob[64:80]
    ciphertext = blob[80:-32]
    mac_received = blob[-32:]

    # Вычисляем общий секрет
    shared_point = _ecdh_multiply(private_key, iv)
    shared_secret = shared_point.x.to_bytes(32, 'big')

    salt = iv.x.to_bytes(32, 'big') + iv.y.to_bytes(32, 'big')
    info = b"EC-Stream-Cipher v1"
    enc_key, mac_key = _derive_keys(shared_secret, salt, info)

    expected_mac = hmac.new(mac_key,
                            blob[:64] + nonce + ciphertext,
                            hashlib.sha256).digest()
    if not hmac.compare_digest(mac_received, expected_mac):
        raise ValueError("HMAC не совпадает")

    gamma = _xor_stream(enc_key, nonce, len(ciphertext))
    plaintext = bytes([ciphertext[i] ^ gamma[i] for i in range(len(ciphertext))])
    return plaintext
