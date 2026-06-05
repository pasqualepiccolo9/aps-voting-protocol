# src/voter.py

import secrets
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from src.crypto_utils import (
    generate_rsa_keys,
    encrypt_oaep,
    hash_sha256,
    verify_signature,
    pubkey_to_bytes
)


class Voter:
    """
    Elettore del sistema di voto elettronico.

    Nel protocollo l'elettore:
    - genera una coppia di chiavi;
    - genera un token pseudonimo;
    - richiede al Sistema di Autenticazione la firma del token;
    - cifra il voto con la chiave pubblica dell'Autorità Elettorale;
    - invia all'AE il voto cifrato e il token firmato;
    - conserva la ricevuta per la verifica individuale.
    """

    def __init__(self, voter_id: str):
        self.voter_id = voter_id

        self.private_key, self.public_key = generate_rsa_keys()

        self.token: Optional[str] = None
        self.signed_token: Optional[dict] = None

        self.ballot_id: Optional[str] = None
        self.ciphertext: Optional[bytes] = None
        self.receipt: Optional[dict] = None

    # ──────────────────────────────────────────────
    # CHIAVI DELL'ELETTORE
    # ──────────────────────────────────────────────

    def get_public_key(self) -> RSAPublicKey:
        """Restituisce la chiave pubblica dell'elettore."""
        return self.public_key

    def get_public_key_bytes(self) -> bytes:
        """Restituisce la chiave pubblica dell'elettore serializzata in PEM."""
        return pubkey_to_bytes(self.public_key)

    # ──────────────────────────────────────────────
    # TOKEN PSEUDONIMO
    # ──────────────────────────────────────────────

    def generate_token(self) -> str:
        """
        Genera un token pseudonimo casuale.

        Il token non contiene l'identità reale dell'elettore.
        Verrà inviato al SA per ottenere una firma di autorizzazione.
        """
        self.token = secrets.token_hex(32)
        return self.token

    def request_signed_token(self, auth_server) -> dict:
        """
        Richiede al Sistema di Autenticazione la firma del token.

        Il SA conosce voter_id, ma il token firmato che verrà presentato
        all'Autorità Elettorale non contiene l'identità reale dell'elettore.
        """
        if self.token is None:
            self.generate_token()

        self.signed_token = auth_server.issue_token(self.voter_id, self.token)
        return self.signed_token

    # ──────────────────────────────────────────────
    # CIFRATURA DEL VOTO
    # ──────────────────────────────────────────────

    def encrypt_vote(self, vote: str, ae_public_key: RSAPublicKey) -> bytes:
        """
        Cifra il voto con la chiave pubblica dell'Autorità Elettorale.

        La cifratura usa RSA-OAEP, coerentemente con il WP2.
        """
        self.ciphertext = encrypt_oaep(ae_public_key, vote.encode("utf-8"))
        return self.ciphertext

    def generate_ballot_id(self) -> str:
        """
        Genera l'identificativo pubblico della scheda.

        Questo identificativo sarà pubblicato nel Bulletin Board come id_i.
        Non coincide con l'identità reale dell'elettore.
        """
        self.ballot_id = "ballot_" + secrets.token_hex(16)
        return self.ballot_id

    # ──────────────────────────────────────────────
    # PACCHETTO DA INVIARE ALL'AUTORITÀ ELETTORALE
    # ──────────────────────────────────────────────

    def prepare_ballot_packet(self, vote: str, ae_public_key: RSAPublicKey) -> dict:
        """
        Prepara il pacchetto da inviare all'Autorità Elettorale.

        Il pacchetto contiene:
        - id: identificativo pubblico della scheda;
        - ciphertext: voto cifrato;
        - signed_token: token firmato dal SA.

        Non contiene voter_id, così l'AE non riceve l'identità reale dell'elettore.
        """
        if self.signed_token is None:
            raise ValueError("Token firmato mancante. Richiedere prima il token al SA.")

        if self.ballot_id is None:
            self.generate_ballot_id()

        ciphertext = self.encrypt_vote(vote, ae_public_key)

        return {
            "id": self.ballot_id,
            "ciphertext": ciphertext.hex(),
            "signed_token": self.signed_token
        }

    # ──────────────────────────────────────────────
    # RICEVUTA DELL'AUTORITÀ ELETTORALE
    # ──────────────────────────────────────────────

    def store_receipt(self, receipt: dict) -> None:
        """
        Conserva la ricevuta restituita dall'Autorità Elettorale.

        La ricevuta sarà usata per la verifica individuale.
        """
        required_fields = {"index", "id", "ciphertext", "signature"}

        if not required_fields.issubset(receipt.keys()):
            raise ValueError(f"La ricevuta deve contenere i campi: {required_fields}")

        self.receipt = receipt

    # ──────────────────────────────────────────────
    # VERIFICA INDIVIDUALE
    # ──────────────────────────────────────────────

    def verify_individual_inclusion(self, bulletin_board, ae_public_key: RSAPublicKey, official_root_hex: Optional[str] = None) -> bool:
        """
        Verifica individuale dell'elettore.

        L'elettore controlla che:
        1. la ricevuta sia presente;
        2. la voce pubblicata nel Bulletin Board coincida con la ricevuta;
        3. la firma dell'AE su id || H(ciphertext) sia valida;
        4. la voce sia inclusa nel Merkle Tree del Bulletin Board.
        """
        if self.receipt is None:
            return False

        try:
            index = self.receipt["index"]
            entry = bulletin_board.get_entry(index)

            if entry["id"] != self.receipt["id"]:
                return False

            if entry["ciphertext"] != self.receipt["ciphertext"]:
                return False

            if entry["signature"] != self.receipt["signature"]:
                return False

            ciphertext_bytes = bytes.fromhex(entry["ciphertext"])
            message = entry["id"].encode("utf-8") + hash_sha256(ciphertext_bytes)
            signature_bytes = bytes.fromhex(entry["signature"])

            signature_valid = verify_signature(ae_public_key, message, signature_bytes)

            if official_root_hex is not None:
                official_root = bytes.fromhex(official_root_hex)
                inclusion_valid = bulletin_board.verify_entry_inclusion_against_root(
                    index=index,
                    root=official_root
                )
            else:
                inclusion_valid = bulletin_board.verify_entry_inclusion(index)

            return signature_valid and inclusion_valid

        except (KeyError, ValueError, IndexError):
            return False