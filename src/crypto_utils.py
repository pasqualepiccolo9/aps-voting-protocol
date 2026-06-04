# src/crypto_utils.py

import hashlib
import json

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives import hashes, serialization


# ──────────────────────────────────────────────
# GENERAZIONE CHIAVI RSA
# ──────────────────────────────────────────────

def genera_chiavi_rsa() -> tuple[RSAPrivateKey, RSAPublicKey]:
    """Genera una coppia di chiavi RSA a 2048 bit."""
    chiave_privata = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    chiave_pubblica = chiave_privata.public_key()
    return chiave_privata, chiave_pubblica


# ──────────────────────────────────────────────
# CIFRATURA / DECIFRATURA RSA-OAEP
# ──────────────────────────────────────────────

def cifra_oaep(chiave_pubblica: RSAPublicKey, messaggio: bytes) -> bytes:
    """Cifra un messaggio con RSA-OAEP usando SHA-256."""
    return chiave_pubblica.encrypt(
        messaggio,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def decifra_oaep(chiave_privata: RSAPrivateKey, ciphertext: bytes) -> bytes:
    """Decifra un ciphertext RSA-OAEP."""
    return chiave_privata.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


# ──────────────────────────────────────────────
# FIRMA DIGITALE / VERIFICA
# ──────────────────────────────────────────────

def firma(chiave_privata: RSAPrivateKey, messaggio: bytes) -> bytes:
    """Firma un messaggio con RSA-PSS e SHA-256."""
    return chiave_privata.sign(
        messaggio,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def verifica_firma(chiave_pubblica: RSAPublicKey, messaggio: bytes, firma_bytes: bytes) -> bool:
    """Verifica la firma di un messaggio. Restituisce True se valida."""
    try:
        chiave_pubblica.verify(
            firma_bytes,
            messaggio,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


# ──────────────────────────────────────────────
# HASH SHA-256
# ──────────────────────────────────────────────

def hash_sha256(dati: bytes) -> bytes:
    """Calcola SHA-256 di un dato in bytes."""
    return hashlib.sha256(dati).digest()


def hash_sha256_hex(dati: bytes) -> str:
    """Calcola SHA-256 e restituisce la stringa esadecimale."""
    return hashlib.sha256(dati).hexdigest()


# ──────────────────────────────────────────────
# SERIALIZZAZIONE MESSAGGI
# ──────────────────────────────────────────────

def serializza(dato: dict) -> bytes:
    """Serializza un dizionario in bytes JSON ordinato."""
    return json.dumps(dato, sort_keys=True, default=str).encode("utf-8")


def pubkey_to_bytes(chiave_pubblica: RSAPublicKey) -> bytes:
    """Serializza una chiave pubblica RSA in formato PEM."""
    return chiave_pubblica.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )