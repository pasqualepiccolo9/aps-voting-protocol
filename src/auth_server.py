# src/auth_server.py

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from src.crypto_utils import (
    generate_rsa_keys,
    sign,
    verify_signature,
    hash_sha256,
    pubkey_to_bytes
)


class AuthServer:
    """
    Sistema di Autenticazione (SA).

    Il SA conosce l'identità reale degli elettori e verifica il loro diritto
    al voto. Se l'elettore è autorizzato, il SA firma un token pseudonimo
    generato dall'elettore.

    Il token firmato verrà poi presentato all'Autorità Elettorale.
    L'AE potrà verificare la firma del SA, ma non riceverà l'identità reale
    dell'elettore.
    """

    def __init__(self):
        self.private_key, self.public_key = generate_rsa_keys()

        self.eligible_voters: dict[str, RSAPublicKey] = {}
        self.issued_tokens: dict[str, dict] = {}

    # ──────────────────────────────────────────────
    # REGISTRAZIONE ELETTORI
    # ──────────────────────────────────────────────

    def register_voter(self, voter_id: str, voter_public_key: RSAPublicKey) -> None:
        """
        Registra un elettore avente diritto.

        voter_id identifica l'elettore presso il SA.
        La chiave pubblica dell'elettore simula il legame tra identità
        istituzionale e credenziale crittografica.
        """
        if voter_id in self.eligible_voters:
            raise ValueError("Elettore già registrato.")

        self.eligible_voters[voter_id] = voter_public_key

    def is_eligible(self, voter_id: str) -> bool:
        """Restituisce True se l'elettore è presente nella lista degli aventi diritto."""
        return voter_id in self.eligible_voters

    # ──────────────────────────────────────────────
    # FIRMA DEL TOKEN
    # ──────────────────────────────────────────────

    def issue_token(self, voter_id: str, token: str) -> dict:
        """
        Firma un token pseudonimo generato dall'elettore.

        Il SA non inserisce l'identità reale dell'elettore nel token firmato.
        Registra però internamente che quell'elettore ha già ricevuto
        un'autorizzazione, impedendo una seconda emissione.
        """
        if voter_id not in self.eligible_voters:
            raise ValueError("Elettore non avente diritto.")

        if voter_id in self.issued_tokens:
            raise ValueError("Token già emesso per questo elettore.")

        token_hash = hash_sha256(token.encode("utf-8"))
        token_signature = sign(self.private_key, token_hash)

        signed_token = {
            "token": token,
            "signature": token_signature.hex()
        }

        self.issued_tokens[voter_id] = signed_token

        return signed_token

    # ──────────────────────────────────────────────
    # VERIFICA TOKEN
    # ──────────────────────────────────────────────

    def verify_token(self, signed_token: dict) -> bool:
        """
        Verifica che il token sia stato firmato dal SA.

        Nel protocollo questa verifica sarà eseguita principalmente
        dall'Autorità Elettorale usando la chiave pubblica del SA.
        """
        try:
            token = signed_token["token"]
            signature_bytes = bytes.fromhex(signed_token["signature"])

            token_hash = hash_sha256(token.encode("utf-8"))

            return verify_signature(self.public_key, token_hash, signature_bytes)

        except (KeyError, ValueError):
            return False

    def get_public_key(self) -> RSAPublicKey:
        """Restituisce la chiave pubblica del SA."""
        return self.public_key

    def get_public_key_bytes(self) -> bytes:
        """Restituisce la chiave pubblica del SA serializzata in PEM."""
        return pubkey_to_bytes(self.public_key)