# src/crypto_utils.py

import hashlib
import json

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives import hashes, serialization


# ──────────────────────────────────────────────
# GENERAZIONE CHIAVI RSA
# ──────────────────────────────────────────────

def generate_rsa_keys() -> tuple[RSAPrivateKey, RSAPublicKey]:
    """Genera una coppia di chiavi RSA a 2048 bit."""

    # public_exponent=65537 è il valore comunemente usato nelle implementazioni RSA.
    # key_size=2048 rappresenta una dimensione standard adeguata per questa simulazione.
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key


# ──────────────────────────────────────────────
# CIFRATURA / DECIFRATURA RSA-OAEP
# ──────────────────────────────────────────────

def encrypt_oaep(public_key: RSAPublicKey, message: bytes) -> bytes:
    """Cifra un messaggio con RSA-OAEP usando SHA-256."""

    # OAEP introduce padding probabilistico: lo stesso messaggio cifrato più volte
    # produce ciphertext diversi, evitando il comportamento deterministico di RSA textbook.
    return public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def decrypt_oaep(private_key: RSAPrivateKey, ciphertext: bytes) -> bytes:
    """Decifra un ciphertext RSA-OAEP."""

    # La decifratura deve usare gli stessi parametri OAEP usati in cifratura.
    return private_key.decrypt(
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

def sign(private_key: RSAPrivateKey, message: bytes) -> bytes:
    """Firma un messaggio con RSA-PSS e SHA-256."""

    # RSA-PSS è uno schema di firma probabilistico e più adatto rispetto
    # alla firma RSA "base"; SHA-256 viene usato come funzione hash.
    return private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def verify_signature(public_key: RSAPublicKey, message: bytes, signature_bytes: bytes) -> bool:
    """Verifica la firma di un messaggio. Restituisce True se valida."""

    # La verifica solleva un'eccezione se la firma non è valida.
    # Per semplificare l'uso negli altri moduli, convertiamo l'esito in True/False.
    try:
        public_key.verify(
            signature_bytes,
            message,
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

def hash_sha256(data: bytes) -> bytes:
    """Calcola SHA-256 di un dato in bytes."""
    return hashlib.sha256(data).digest()


def hash_sha256_hex(data: bytes) -> str:
    """Calcola SHA-256 e restituisce la stringa esadecimale."""
    return hashlib.sha256(data).hexdigest()


# ──────────────────────────────────────────────
# SERIALIZZAZIONE MESSAGGI
# ──────────────────────────────────────────────

def serialize(data: dict) -> bytes:
    """Serializza un dizionario in bytes JSON ordinato."""

    # sort_keys=True rende la serializzazione deterministica:
    # lo stesso dizionario produce sempre la stessa sequenza di byte.
    return json.dumps(data, sort_keys=True, default=str).encode("utf-8")


def pubkey_to_bytes(public_key: RSAPublicKey) -> bytes:
    """Serializza una chiave pubblica RSA in formato PEM."""

    # Il formato PEM è comodo per salvare, stampare o confrontare chiavi pubbliche.
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )