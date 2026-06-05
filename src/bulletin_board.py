# src/bulletin_board.py
from typing import Optional
from copy import deepcopy

from src.crypto_utils import serialize, hash_sha256_hex
from src.merkle_tree import MerkleTree, verify_proof


class BulletinBoard:
    """
    Bulletin Board pubblico append-only.

    Nel protocollo rappresenta l'urna pubblica: ogni scheda accettata
    dall'Autorità Elettorale viene registrata come voce del Bulletin Board.

    Ogni voce segue la struttura prevista dal WP2:
    B_i = (id_i, ct_i, sigma_AE(id_i || H(ct_i))).

    Nel codice questi campi sono rappresentati come:
    - id
    - ciphertext
    - signature
    """

    def __init__(self):
        self.entries: list[dict] = []
        self.merkle_tree: Optional[MerkleTree] = None

    # ──────────────────────────────────────────────
    # INSERIMENTO DELLE VOCI
    # ──────────────────────────────────────────────

    def add_entry(self, entry: dict) -> int:
        """
        Aggiunge una nuova voce al Bulletin Board.

        La voce deve contenere obbligatoriamente:
        - id: identificativo pubblico della scheda;
        - ciphertext: voto cifrato;
        - signature: firma dell'Autorità Elettorale su id || H(ciphertext).

        Restituisce l'indice della voce inserita, che sarà usato
        dall'elettore per la verifica individuale.
        """
        required_fields = {"id", "ciphertext", "signature"}

        if not required_fields.issubset(entry.keys()):
            raise ValueError(f"La voce deve contenere i campi: {required_fields}")

        self.entries.append(entry)

        # Ogni nuovo inserimento invalida il Merkle Tree precedente.
        # La radice verrà ricalcolata automaticamente quando richiesta.
        self.merkle_tree = None

        return len(self.entries) - 1

    def get_entry(self, index: int) -> dict:
        """
        Restituisce una copia di una voce del Bulletin Board con il suo indice.
        La copia evita che codice esterno possa modificare direttamente il registro interno, preservando il comportamento append-only
        """
        if index < 0 or index >= len(self.entries):
            raise IndexError("Indice della voce non valido.")

        return deepcopy(self.entries[index])

    def get_entries(self) -> list[dict]:
        """
        Restituisce una copia di tutte le voci pubbliche del Bulletin Board.

        Viene restituita una copia della lista per evitare modifiche dirette
        alla struttura interna del registro.
        """
        return deepcopy(self.entries)

    # ──────────────────────────────────────────────
    # SERIALIZZAZIONE E HASH DELLE VOCI
    # ──────────────────────────────────────────────

    def serialize_entry(self, index: int) -> bytes:
        """Serializza una voce del Bulletin Board in modo deterministico."""
        entry = self.get_entry(index)
        return serialize(entry)

    def hash_entry_hex(self, index: int) -> str:
        """Restituisce l'hash SHA-256 esadecimale di una voce."""
        return hash_sha256_hex(self.serialize_entry(index))

    def _serialized_entries(self) -> list[bytes]:
        """Restituisce tutte le voci serializzate, pronte per il Merkle Tree."""
        return [serialize(entry) for entry in self.entries]

    # ──────────────────────────────────────────────
    # MERKLE TREE
    # ──────────────────────────────────────────────

    def build_merkle_tree(self) -> MerkleTree:
        """
        Costruisce il Merkle Tree sulle voci attualmente presenti.

        Se il Bulletin Board è vuoto, non è possibile costruire una radice.
        """
        if not self.entries:
            raise ValueError("Impossibile costruire il Merkle Tree: Bulletin Board vuoto.")

        self.merkle_tree = MerkleTree(self._serialized_entries())
        return self.merkle_tree

    def get_merkle_tree(self) -> MerkleTree:
        """
        Restituisce il Merkle Tree corrente.

        Se non esiste oppure è stato invalidato da un nuovo inserimento,
        viene ricostruito automaticamente.
        """
        if self.merkle_tree is None:
            return self.build_merkle_tree()

        return self.merkle_tree

    def get_merkle_root(self) -> bytes:
        """Restituisce la Merkle root in bytes."""
        return self.get_merkle_tree().root()

    def get_merkle_root_hex(self) -> str:
        """Restituisce la Merkle root in formato esadecimale."""
        return self.get_merkle_tree().root_hex()

    def get_proof(self, index: int) -> list[tuple[str, bytes]]:
        """Restituisce la Merkle proof della voce all'indice indicato."""
        return self.get_merkle_tree().generate_proof(index)

    def verify_entry_inclusion(self, index: int) -> bool:
        """
        Verifica che una voce sia inclusa nel Merkle Tree corrente.

        Questa funzione simula la verifica individuale di inclusione:
        si prende la voce pubblicata, si genera la proof e si controlla
        che ricostruisca la Merkle root pubblicata.
        """
        entry_bytes = self.serialize_entry(index)
        proof = self.get_proof(index)
        root = self.get_merkle_root()

        return verify_proof(entry_bytes, index, proof, root)

    def verify_entry_inclusion_against_root(self, index: int, root: bytes) -> bool:
        """
        Verifica che una voce sia inclusa rispetto a una Merkle root specifica.

        Questo metodo è utile dopo la chiusura delle urne, quando l'AE pubblica
        una root_B firmata. L'elettore può così verificare la propria scheda
        rispetto alla root ufficiale, e non solo rispetto alla root corrente.
        """
        entry_bytes = self.serialize_entry(index)
        proof = self.get_proof(index)

        return verify_proof(entry_bytes, index, proof, root)