# src/verifier.py

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from src.crypto_utils import hash_sha256, verify_signature, serialize


class PublicVerifier:
    """
    Verificatore Pubblico.

    Nel protocollo il verificatore pubblico controlla le informazioni pubblicate
    dall'Autorità Elettorale dopo la chiusura delle urne.

    In particolare verifica:
    - il formato delle voci del Bulletin Board;
    - la firma dell'AE su ogni voce B_i;
    - l'inclusione delle voci nel Merkle Tree;
    - la firma di chiusura sigma_close su root_B || m;
    - la firma del risultato finale sigma_R;
    - la coerenza numerica tra Bulletin Board e risultato pubblicato.

    Il verificatore non decifra i voti: la decifrazione resta compito dell'AE.
    """

    def __init__(self, ae_signing_public_key: RSAPublicKey):
        self.ae_signing_public_key = ae_signing_public_key

    # ──────────────────────────────────────────────
    # VERIFICA DEL FORMATO DELLE VOCI
    # ──────────────────────────────────────────────

    def is_valid_entry_format(self, entry: dict) -> bool:
        """
        Controlla che una voce del Bulletin Board abbia il formato previsto.

        Ogni voce deve avere la forma:
        B_i = (id_i, ct_i, sigma_AE(id_i || H(ct_i))).

        Nel codice:
        - id
        - ciphertext
        - signature
        """
        required_fields = {"id", "ciphertext", "signature"}

        if not required_fields.issubset(entry.keys()):
            return False

        if not isinstance(entry["id"], str):
            return False

        if not isinstance(entry["ciphertext"], str):
            return False

        if not isinstance(entry["signature"], str):
            return False

        return True

    # ──────────────────────────────────────────────
    # VERIFICA DELLA FIRMA DELL'AE SULLE VOCI
    # ──────────────────────────────────────────────

    def verify_entry_signature(self, entry: dict) -> bool:
        """
        Verifica la firma dell'Autorità Elettorale su una voce del Bulletin Board.

        L'AE firma:
        id_i || H(ct_i)
        """
        if not self.is_valid_entry_format(entry):
            return False

        try:
            ballot_id = entry["id"]
            ciphertext_bytes = bytes.fromhex(entry["ciphertext"])
            signature_bytes = bytes.fromhex(entry["signature"])

            message = ballot_id.encode("utf-8") + hash_sha256(ciphertext_bytes)

            return verify_signature(
                self.ae_signing_public_key,
                message,
                signature_bytes
            )

        except ValueError:
            return False

    # ──────────────────────────────────────────────
    # VERIFICA DI INCLUSIONE NEL MERKLE TREE
    # ──────────────────────────────────────────────

    def verify_entry_inclusion(self, bulletin_board, index: int) -> bool:
        """
        Verifica che la voce all'indice indicato sia inclusa nel Merkle Tree.

        Usa la Merkle proof generata dal Bulletin Board.
        """
        try:
            return bulletin_board.verify_entry_inclusion(index)
        except (IndexError, ValueError):
            return False

    # ──────────────────────────────────────────────
    # VERIFICA COMPLETA DEL BULLETIN BOARD
    # ──────────────────────────────────────────────

    def verify_bulletin_board(self, bulletin_board) -> bool:
        """
        Verifica tutte le voci pubblicate nel Bulletin Board.

        Per ogni voce controlla:
        1. formato corretto;
        2. firma AE valida;
        3. inclusione nel Merkle Tree.
        """
        entries = bulletin_board.get_entries()

        if not entries:
            return False

        for index, entry in enumerate(entries):
            if not self.is_valid_entry_format(entry):
                return False

            if not self.verify_entry_signature(entry):
                return False

            if not self.verify_entry_inclusion(bulletin_board, index):
                return False

        return True

    # ──────────────────────────────────────────────
    # VERIFICA DEL MESSAGGIO DI CHIUSURA
    # ──────────────────────────────────────────────

    def verify_close_message(self, bulletin_board, close_message: dict) -> bool:
        """
        Verifica il messaggio di chiusura pubblicato dall'AE.

        Il messaggio deve contenere:
        - root_B: Merkle root in formato esadecimale;
        - m: numero di schede pubblicate;
        - sigma_close: firma AE su root_B || m.

        Coerentemente con il WP2:
        sigma_close = Sign_sk_sign_AE(root_B || m)
        """
        required_fields = {"root_B", "m", "sigma_close"}

        if not required_fields.issubset(close_message.keys()):
            return False

        try:
            root_hex = close_message["root_B"]
            m = close_message["m"]
            sigma_close = bytes.fromhex(close_message["sigma_close"])

            if not isinstance(root_hex, str):
                return False

            if not isinstance(m, int):
                return False

            if m != len(bulletin_board.get_entries()):
                return False

            if root_hex != bulletin_board.get_merkle_root_hex():
                return False

            root_bytes = bytes.fromhex(root_hex)
            message = root_bytes + m.to_bytes(8, byteorder="big")

            return verify_signature(
                self.ae_signing_public_key,
                message,
                sigma_close
            )

        except (ValueError, TypeError):
            return False

    # ──────────────────────────────────────────────
    # VERIFICA DEL RISULTATO FIRMATO
    # ──────────────────────────────────────────────

    def verify_signed_results(self, bulletin_board, signed_results: dict) -> bool:
        """
        Verifica il risultato finale firmato dall'AE.

        Il risultato firmato deve avere forma:
        {
            "results": {
                "Candidato A": ...,
                "Candidato B": ...,
                "Candidato C": ...,
                "NULL": ...,
                "root_B": "..."
            },
            "sigma_r": "..."
        }

        Coerentemente con il WP2:
        R = (N_1, N_2, N_3, N_null, root_B)
        sigma_R = Sign_sk_sign_AE(R)
        """
        required_fields = {"results", "sigma_r"}

        if not required_fields.issubset(signed_results.keys()):
            return False

        try:
            results = signed_results["results"]
            sigma_r = bytes.fromhex(signed_results["sigma_r"])

            if not isinstance(results, dict):
                return False

            if "root_B" not in results:
                return False

            if results["root_B"] != bulletin_board.get_merkle_root_hex():
                return False

            # La firma deve essere verificata sugli stessi byte serializzati
            # usati dall'AE in tally_votes().
            result_bytes = serialize(results)

            signature_valid = verify_signature(
                self.ae_signing_public_key,
                result_bytes,
                sigma_r
            )

            if not signature_valid:
                return False

            return self.verify_result_consistency(bulletin_board, results)

        except (ValueError, TypeError):
            return False

    # ──────────────────────────────────────────────
    # VERIFICA DI COERENZA DEL RISULTATO
    # ──────────────────────────────────────────────

    def verify_result_consistency(self, bulletin_board, results: dict) -> bool:
        """
        Verifica una coerenza minima tra Bulletin Board e risultato pubblicato.

        Il verificatore pubblico non decifra le schede, quindi non può sapere
        se ogni ciphertext sia stato contato nel candidato corretto.

        Può però controllare che:
        - root_B nel risultato coincida con la Merkle root pubblica;
        - la somma dei voti dichiarati coincida con il numero di schede;
        - i valori dei conteggi siano interi non negativi.
        """
        if not isinstance(results, dict):
            return False

        if "root_B" not in results:
            return False

        if results["root_B"] != bulletin_board.get_merkle_root_hex():
            return False

        total_declared_votes = 0

        for key, value in results.items():
            if key == "root_B":
                continue

            if not isinstance(value, int):
                return False

            if value < 0:
                return False

            total_declared_votes += value

        total_published_ballots = len(bulletin_board.get_entries())

        return total_declared_votes == total_published_ballots

    # ──────────────────────────────────────────────
    # VERIFICA UNIVERSALE
    # ──────────────────────────────────────────────

    def verify_universal(self, bulletin_board, close_message: dict, signed_results: dict) -> bool:
        """
        Esegue la verifica universale disponibile nella simulazione.

        Controlla:
        - validità delle voci del Bulletin Board;
        - firma AE su ogni voce;
        - inclusione delle voci nel Merkle Tree;
        - firma di chiusura sigma_close;
        - firma del risultato sigma_R;
        - coerenza tra root_B, numero di schede e risultati.

        Questa verifica non dimostra pubblicamente la correttezza della
        decifrazione candidato per candidato, perché il protocollo non usa
        prove a conoscenza zero o cifratura omomorfica.
        """
        bulletin_board_valid = self.verify_bulletin_board(bulletin_board)
        close_message_valid = self.verify_close_message(bulletin_board, close_message)
        results_valid = self.verify_signed_results(bulletin_board, signed_results)

        return bulletin_board_valid and close_message_valid and results_valid