# src/electoral_authority.py

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from src.bulletin_board import BulletinBoard
from src.crypto_utils import (
    generate_rsa_keys,
    decrypt_oaep,
    hash_sha256,
    sign,
    verify_signature,
    serialize,
    pubkey_to_bytes
)


class ElectoralAuthority:
    """
    Autorità Elettorale (AE).

    Nel protocollo l'AE riceve le schede cifrate, verifica che il token
    sia stato firmato dal Sistema di Autenticazione e registra la scheda
    nel Bulletin Board.

    Coerentemente con il WP2, l'AE usa due coppie di chiavi distinte:
    - una coppia per cifrare/decifrare le schede (pk_AE, sk_AE);
    - una coppia per firmare ricevute, chiusura e risultati (pk_sign_AE, sk_sign_AE).
    """

    def __init__(self, auth_server_public_key: RSAPublicKey, bulletin_board: BulletinBoard):
        self.encryption_private_key, self.encryption_public_key = generate_rsa_keys()
        self.signing_private_key, self.signing_public_key = generate_rsa_keys()

        self.auth_server_public_key = auth_server_public_key
        self.bulletin_board = bulletin_board

        self.used_tokens: set[str] = set()
        self.is_closed = False

    # ──────────────────────────────────────────────
    # CHIAVI DELL'AUTORITÀ ELETTORALE
    # ──────────────────────────────────────────────

    def get_encryption_public_key(self) -> RSAPublicKey:
        """Restituisce la chiave pubblica dell'AE usata per cifrare i voti."""
        return self.encryption_public_key

    def get_signing_public_key(self) -> RSAPublicKey:
        """Restituisce la chiave pubblica dell'AE usata per verificare le firme."""
        return self.signing_public_key

    def get_encryption_public_key_bytes(self) -> bytes:
        """Restituisce la chiave pubblica di cifratura dell'AE in formato PEM."""
        return pubkey_to_bytes(self.encryption_public_key)

    def get_signing_public_key_bytes(self) -> bytes:
        """Restituisce la chiave pubblica di firma dell'AE in formato PEM."""
        return pubkey_to_bytes(self.signing_public_key)

    # ──────────────────────────────────────────────
    # VERIFICA DEL TOKEN FIRMATO DAL SA
    # ──────────────────────────────────────────────

    def verify_signed_token(self, signed_token: dict) -> bool:
        """
        Verifica che il token sia stato firmato dal Sistema di Autenticazione.

        Il SA firma H(token), quindi l'AE ricostruisce H(token)
        e verifica la firma usando la chiave pubblica del SA.
        """
        try:
            token = signed_token["token"]
            signature_bytes = bytes.fromhex(signed_token["signature"])
            token_hash = hash_sha256(token.encode("utf-8"))
            return verify_signature(
                self.auth_server_public_key,
                token_hash,
                signature_bytes
            )
        except (KeyError, ValueError):
            return False

    # ──────────────────────────────────────────────
    # RICEZIONE E REGISTRAZIONE DELLA SCHEDA
    # ──────────────────────────────────────────────

    def submit_ballot(self, ballot_packet: dict) -> dict:
        """
        Riceve una scheda cifrata e la registra nel Bulletin Board.

        Il pacchetto deve contenere:
        - id: identificativo pubblico della scheda;
        - ciphertext: voto cifrato in formato esadecimale;
        - signed_token: token firmato dal SA.

        L'AE firma id || H(ciphertext) e produce la voce:
        B_i = (id_i, ct_i, sigma_AE(id_i || H(ct_i))).

        Restituisce la ricevuta all'elettore.
        """
        if self.is_closed:
            raise ValueError("Urne chiuse: non è possibile registrare nuove schede.")

        required_fields = {"id", "ciphertext", "signed_token"}
        if not required_fields.issubset(ballot_packet.keys()):
            raise ValueError(f"Il pacchetto deve contenere i campi: {required_fields}")

        signed_token = ballot_packet["signed_token"]

        if not self.verify_signed_token(signed_token):
            raise ValueError("Token non valido o firma del SA non verificabile.")

        token_value = signed_token["token"]

        if token_value in self.used_tokens:
            raise ValueError("Token già utilizzato.")

        ballot_id = ballot_packet["id"]
        ciphertext_hex = ballot_packet["ciphertext"]
        ciphertext_bytes = bytes.fromhex(ciphertext_hex)

        # Firma su id || H(ciphertext), coerente con WP2:
        # sigma_AE(id_i || H(ct_i))
        message = ballot_id.encode("utf-8") + hash_sha256(ciphertext_bytes)
        ae_signature = sign(self.signing_private_key, message).hex()

        entry = {
            "id": ballot_id,
            "ciphertext": ciphertext_hex,
            "signature": ae_signature
        }

        index = self.bulletin_board.add_entry(entry)

        # Il token viene marcato come usato solo dopo la registrazione corretta.
        self.used_tokens.add(token_value)

        receipt = {
            "index": index,
            "id": ballot_id,
            "ciphertext": ciphertext_hex,
            "signature": ae_signature
        }

        return receipt

    # ──────────────────────────────────────────────
    # CHIUSURA URNE
    # ──────────────────────────────────────────────

    def close_election(self) -> dict:
        """
        Chiude le urne e pubblica la firma di chiusura.

        Coerentemente con il WP2:
        sigma_close = Sign_sk_sign_AE(root_B || m)

        dove root_B è la radice del Merkle Tree e m è il numero di schede.
        Restituisce root_B, m e sigma_close.
        """
        self.is_closed = True

        root = self.bulletin_board.get_merkle_root()
        m = len(self.bulletin_board.get_entries())

        # Messaggio di chiusura: root_B || m (m codificato su 8 byte)
        message = root + m.to_bytes(8, byteorder="big")
        sigma_close = sign(self.signing_private_key, message)

        return {
            "root_B": root.hex(),
            "m": m,
            "sigma_close": sigma_close.hex()
        }

    # ──────────────────────────────────────────────
    # SCRUTINIO
    # ──────────────────────────────────────────────

    def decrypt_ballot(self, ciphertext_hex: str) -> str:
        """Decifra una singola scheda cifrata usando la chiave privata di cifratura."""
        ciphertext_bytes = bytes.fromhex(ciphertext_hex)
        plaintext = decrypt_oaep(self.encryption_private_key, ciphertext_bytes)
        return plaintext.decode("utf-8")

    def tally_votes(self, valid_candidates: list[str]) -> dict:
        """
        Esegue lo scrutinio delle schede presenti nel Bulletin Board.

        Coerentemente con il WP2:
        R = (N_1, N_2, N_3, N_null, root_B)
        sigma_R = Sign_sk_sign_AE(R)

        Restituisce il risultato R e la firma sigma_R.
        """
        if not self.is_closed:
            raise ValueError("Lo scrutinio può avvenire solo dopo la chiusura delle urne.")

        results = {candidate: 0 for candidate in valid_candidates}
        results["NULL"] = 0

        for entry in self.bulletin_board.get_entries():
            try:
                vote = self.decrypt_ballot(entry["ciphertext"])
                if vote in results:
                    results[vote] += 1
                else:
                    results["NULL"] += 1
            except Exception:
                results["NULL"] += 1

        # Aggiunge root_B al risultato, coerente con R = (N_1,...,N_null, root_B)
        results["root_B"] = self.bulletin_board.get_merkle_root_hex()

        # Firma il risultato finale: sigma_R = Sign(R)
        result_bytes = serialize(results)
        sigma_r = sign(self.signing_private_key, result_bytes)

        return {
            "results": results,
            "sigma_r": sigma_r.hex()
        }