# src/merkle_tree.py

from src.crypto_utils import hash_sha256


class MerkleTree:
    """
    Merkle Tree costruito su SHA-256.
    Le foglie sono gli hash delle voci del Bulletin Board.
    """

    def __init__(self, leaves: list[bytes]):
        """
        leaves: lista di dati in bytes, ad esempio voci del Bulletin Board serializzate.
        """
        if not leaves:
            raise ValueError("Il Merkle Tree richiede almeno una foglia.")

        self.original_leaves = leaves
        self.levels = self._build(leaves)

    # ──────────────────────────────────────────────
    # COSTRUZIONE DEL MERKLE TREE
    # ──────────────────────────────────────────────

    def _build(self, leaves: list[bytes]) -> list[list[bytes]]:
        """
        Costruisce tutti i livelli dell'albero dal basso verso la radice.
        Se un livello ha un numero dispari di nodi, l'ultimo viene duplicato.
        """

        # Primo livello: ogni foglia originale viene trasformata nel suo hash.
        current_level = [hash_sha256(leaf) for leaf in leaves]
        levels = [current_level]

        while len(current_level) > 1:
            next_level = []

            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left

                # Ogni nodo padre è hash(left || right).
                # L'ordine left/right è importante per la verifica della proof.
                next_level.append(hash_sha256(left + right))

            current_level = next_level
            levels.append(current_level)

        return levels

    # ──────────────────────────────────────────────
    # RADICE DEL MERKLE TREE
    # ──────────────────────────────────────────────

    def root(self) -> bytes:
        """Restituisce la radice del Merkle Tree."""
        return self.levels[-1][0]

    def root_hex(self) -> str:
        """Restituisce la radice in formato esadecimale."""
        return self.root().hex()

    # ──────────────────────────────────────────────
    # GENERAZIONE DELLA MERKLE PROOF
    # ──────────────────────────────────────────────

    def generate_proof(self, index: int) -> list[tuple[str, bytes]]:
        """
        Genera la Merkle proof per la foglia all'indice dato.

        La proof contiene gli hash dei nodi fratelli necessari per ricostruire
        la radice partendo dalla foglia. Ogni elemento è una coppia:
        - ("L", hash): fratello a sinistra;
        - ("R", hash): fratello a destra.
        """
        if index < 0 or index >= len(self.original_leaves):
            raise IndexError("Indice della foglia non valido.")

        proof = []
        current_index = index

        for level in self.levels[:-1]:
            if current_index % 2 == 0:
                sibling_index = current_index + 1 if current_index + 1 < len(level) else current_index
                proof.append(("R", level[sibling_index]))
            else:
                sibling_index = current_index - 1
                proof.append(("L", level[sibling_index]))

            current_index //= 2

        return proof


# ──────────────────────────────────────────────
# VERIFICA DELLA MERKLE PROOF
# ──────────────────────────────────────────────

def verify_proof(
    leaf: bytes,
    index: int,
    proof: list[tuple[str, bytes]],
    root: bytes
) -> bool:
    """
    Verifica che una foglia appartenga a un Merkle Tree con la radice data.

    La verifica parte dall'hash della foglia e combina progressivamente
    gli hash dei fratelli contenuti nella proof, rispettando l'ordine
    sinistra/destra. Se l'hash finale coincide con la radice, la proof è valida.
    """
    if index < 0:
        return False

    # Si parte dall'hash della foglia originale.
    current_hash = hash_sha256(leaf)

    for direction, sibling in proof:
        if direction == "R":
            current_hash = hash_sha256(current_hash + sibling)
        elif direction == "L":
            current_hash = hash_sha256(sibling + current_hash)
        else:
            return False

    return current_hash == root