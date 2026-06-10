# benchmark.py

import csv
import os
import statistics
import time
import secrets

from src.auth_server import AuthServer
from src.bulletin_board import BulletinBoard
from src.crypto_utils import (
    generate_rsa_keys,
    encrypt_oaep,
    decrypt_oaep,
    sign,
    verify_signature,
    hash_sha256,
    serialize
)
from src.electoral_authority import ElectoralAuthority
from src.merkle_tree import MerkleTree, verify_proof
from src.voter import Voter


OUTPUT_PATH = "outputs/benchmark_results.csv"


def measure_operation(operation, repetitions: int) -> tuple[float, float]:
    """
    Misura tempo medio e deviazione standard di una operazione.

    Restituisce:
    - tempo medio in millisecondi;
    - deviazione standard in millisecondi.
    """
    times = []

    for _ in range(repetitions):
        start = time.perf_counter()
        operation()
        end = time.perf_counter()

        times.append((end - start) * 1000)

    mean_time = statistics.mean(times)
    std_time = statistics.stdev(times) if repetitions > 1 else 0.0

    return mean_time, std_time


def add_result(results: list[dict], operation: str, repetitions: int,
               mean_ms: float, std_ms: float, output_size: int, notes: str) -> None:
    """Aggiunge una riga alla tabella dei benchmark."""
    results.append({
        "operation": operation,
        "repetitions": repetitions,
        "mean_ms": round(mean_ms, 6),
        "std_ms": round(std_ms, 6),
        "output_size_bytes": output_size,
        "notes": notes
    })


def benchmark_crypto_operations(results: list[dict]) -> None:
    """
    Misura le primitive crittografiche principali:
    - generazione chiavi RSA;
    - cifratura/decifratura RSA-OAEP;
    - firma/verifica RSA-PSS;
    - hash SHA-256.
    """

    # La generazione RSA è più costosa, quindi usiamo meno ripetizioni.
    repetitions_keygen = 10
    repetitions_crypto = 100

    mean_ms, std_ms = measure_operation(
        lambda: generate_rsa_keys(),
        repetitions_keygen
    )

    add_result(
        results,
        "Generazione chiavi RSA",
        repetitions_keygen,
        mean_ms,
        std_ms,
        0,
        "Setup iniziale"
    )

    private_key, public_key = generate_rsa_keys()
    message = b"Candidato A"

    ciphertext = encrypt_oaep(public_key, message)
    signature = sign(private_key, message)
    digest = hash_sha256(message)

    mean_ms, std_ms = measure_operation(
        lambda: encrypt_oaep(public_key, message),
        repetitions_crypto
    )

    add_result(
        results,
        "Cifratura voto RSA-OAEP",
        repetitions_crypto,
        mean_ms,
        std_ms,
        len(ciphertext),
        "Operazione lato elettore"
    )

    mean_ms, std_ms = measure_operation(
        lambda: decrypt_oaep(private_key, ciphertext),
        repetitions_crypto
    )

    add_result(
        results,
        "Decifrazione voto RSA-OAEP",
        repetitions_crypto,
        mean_ms,
        std_ms,
        len(message),
        "Operazione lato AE durante scrutinio"
    )

    mean_ms, std_ms = measure_operation(
        lambda: sign(private_key, message),
        repetitions_crypto
    )

    add_result(
        results,
        "Firma RSA-PSS",
        repetitions_crypto,
        mean_ms,
        std_ms,
        len(signature),
        "Firma token, ricevute e risultati"
    )

    mean_ms, std_ms = measure_operation(
        lambda: verify_signature(public_key, message, signature),
        repetitions_crypto
    )

    add_result(
        results,
        "Verifica firma RSA-PSS",
        repetitions_crypto,
        mean_ms,
        std_ms,
        1,
        "Verifica token, ricevute e risultati"
    )

    mean_ms, std_ms = measure_operation(
        lambda: hash_sha256(message),
        repetitions_crypto
    )

    add_result(
        results,
        "Hash SHA-256",
        repetitions_crypto,
        mean_ms,
        std_ms,
        len(digest),
        "Hash di token, ciphertext e voci pubbliche"
    )


def benchmark_merkle_tree(results: list[dict]) -> None:
    """
    Misura costruzione del Merkle Tree e verifica della proof.
    """
    repetitions = 100
    number_of_entries = 100

    leaves = [
        serialize({
            "id": f"ballot_{i}",
            "ciphertext": secrets.token_hex(128),
            "signature": secrets.token_hex(256)
        })
        for i in range(number_of_entries)
    ]

    tree = MerkleTree(leaves)
    proof = tree.generate_proof(10)
    root = tree.root()

    mean_ms, std_ms = measure_operation(
        lambda: MerkleTree(leaves),
        repetitions
    )

    add_result(
        results,
        "Costruzione Merkle Tree",
        repetitions,
        mean_ms,
        std_ms,
        len(root),
        f"Numero foglie: {number_of_entries}"
    )

    mean_ms, std_ms = measure_operation(
        lambda: verify_proof(leaves[10], 10, proof, root),
        repetitions
    )

    add_result(
        results,
        "Verifica Merkle proof",
        repetitions,
        mean_ms,
        std_ms,
        1,
        "Verifica individuale di inclusione"
    )


def benchmark_protocol_operations(results: list[dict]) -> None:
    """
    Misura operazioni del protocollo completo:
    - firma token SA;
    - verifica token AE;
    - submit ballot;
    - scrutinio.
    """
    repetitions = 50

    candidates = ["Candidato A", "Candidato B", "Candidato C"]

    bulletin_board = BulletinBoard()
    auth_server = AuthServer()
    electoral_authority = ElectoralAuthority(
        auth_server_public_key=auth_server.get_public_key(),
        bulletin_board=bulletin_board
    )

    voter = Voter("E01")
    auth_server.register_voter("E01", voter.get_public_key())

    token = voter.generate_token()

    signed_token = auth_server.issue_token("E01", token)

    mean_ms, std_ms = measure_operation(
        lambda: auth_server.verify_token(signed_token),
        repetitions
    )

    add_result(
        results,
        "Verifica token SA",
        repetitions,
        mean_ms,
        std_ms,
        1,
        "Controllo validità token firmato"
    )

    # Per misurare submit_ballot bisogna creare ogni volta un nuovo elettore,
    # perché il token può essere usato una sola volta.
    counter = {"value": 0}

    def submit_single_ballot():
        counter["value"] += 1

        local_voter = Voter(f"BENCH_{counter['value']}")
        auth_server.register_voter(local_voter.voter_id, local_voter.get_public_key())
        local_voter.request_signed_token(auth_server)

        packet = local_voter.prepare_ballot_packet(
            vote="Candidato A",
            ae_public_key=electoral_authority.get_encryption_public_key()
        )

        electoral_authority.submit_ballot(packet)

    mean_ms, std_ms = measure_operation(
        submit_single_ballot,
        repetitions
    )

    add_result(
        results,
        "Invio completo della scheda",
        repetitions,
        mean_ms,
        std_ms,
        0,
        "Registrazione elettore, token, cifratura, verifica AE e inserimento nel Bulletin Board"
    )

    # Scrutinio su un insieme separato di voti.
    tally_board = BulletinBoard()
    tally_auth_server = AuthServer()
    tally_ae = ElectoralAuthority(
        auth_server_public_key=tally_auth_server.get_public_key(),
        bulletin_board=tally_board
    )

    for i in range(50):
        local_voter = Voter(f"TALLY_{i}")
        tally_auth_server.register_voter(local_voter.voter_id, local_voter.get_public_key())
        local_voter.request_signed_token(tally_auth_server)

        vote = candidates[i % len(candidates)]

        packet = local_voter.prepare_ballot_packet(
            vote=vote,
            ae_public_key=tally_ae.get_encryption_public_key()
        )

        tally_ae.submit_ballot(packet)

    tally_ae.close_election()

    mean_ms, std_ms = measure_operation(
        lambda: tally_ae.tally_votes(candidates),
        20
    )

    signed_results = tally_ae.tally_votes(candidates)

    add_result(
        results,
        "Scrutinio 50 voti",
        20,
        mean_ms,
        std_ms,
        len(serialize(signed_results)),
        "Decifrazione e conteggio schede"
    )

def benchmark_university_scenario(results: list[dict]) -> None:
    """
    Misura uno scenario universitario realistico con 28.000 schede.

    La misura è ottimizzata: non vengono generati 28.000 elettori
    e quindi non vengono generate 28.000 coppie di chiavi RSA.
    L'obiettivo è misurare le operazioni che crescono con il numero
    di voti effettivamente pubblicati e scrutinati.
    """
    number_of_votes = 28000
    candidates = ["Candidato A", "Candidato B", "Candidato C"]

    bulletin_board = BulletinBoard()
    auth_server = AuthServer()
    electoral_authority = ElectoralAuthority(
        auth_server_public_key=auth_server.get_public_key(),
        bulletin_board=bulletin_board
    )

    # ──────────────────────────────────────────────
    # CIFRATURA DI 28.000 VOTI
    # ──────────────────────────────────────────────

    ciphertexts = []

    start = time.perf_counter()

    for i in range(number_of_votes):
        vote = candidates[i % len(candidates)]
        ciphertext = encrypt_oaep(
            electoral_authority.get_encryption_public_key(),
            vote.encode("utf-8")
        )
        ciphertexts.append(ciphertext)

    end = time.perf_counter()

    add_result(
        results,
        "Scenario universitario: cifratura 28000 voti",
        1,
        (end - start) * 1000,
        0.0,
        sum(len(ct) for ct in ciphertexts),
        "Cifratura RSA-OAEP di tutte le schede"
    )

    # ──────────────────────────────────────────────
    # PUBBLICAZIONE DI 28.000 SCHEDE NEL BULLETIN BOARD
    # ──────────────────────────────────────────────

    start = time.perf_counter()

    for i, ciphertext in enumerate(ciphertexts):
        ballot_id = f"ballot_{i:05d}"
        ciphertext_hex = ciphertext.hex()

        message = ballot_id.encode("utf-8") + hash_sha256(ciphertext)
        ae_signature = sign(
            electoral_authority.signing_private_key,
            message
        ).hex()

        entry = {
            "id": ballot_id,
            "ciphertext": ciphertext_hex,
            "signature": ae_signature
        }

        bulletin_board.add_entry(entry)

    end = time.perf_counter()

    add_result(
        results,
        "Scenario universitario: pubblicazione 28000 schede",
        1,
        (end - start) * 1000,
        0.0,
        0,
        "Firma AE delle voci e inserimento nel Bulletin Board"
    )

    # ──────────────────────────────────────────────
    # COSTRUZIONE MERKLE TREE
    # ──────────────────────────────────────────────

    start = time.perf_counter()
    root = bulletin_board.get_merkle_root()
    end = time.perf_counter()

    add_result(
        results,
        "Scenario universitario: Merkle Tree 28000 schede",
        1,
        (end - start) * 1000,
        0.0,
        len(root),
        "Costruzione Merkle Tree sul Bulletin Board completo"
    )

    # ──────────────────────────────────────────────
    # VERIFICA MERKLE PROOF
    # ──────────────────────────────────────────────

    proof_index = number_of_votes // 2
    proof = bulletin_board.get_proof(proof_index)
    entry = bulletin_board.serialize_entry(proof_index)

    start = time.perf_counter()
    proof_valid = verify_proof(entry, proof_index, proof, root)
    end = time.perf_counter()

    add_result(
        results,
        "Scenario universitario: verifica Merkle proof",
        1,
        (end - start) * 1000,
        0.0,
        1,
        f"Proof valida: {proof_valid}"
    )

    # ──────────────────────────────────────────────
    # SCRUTINIO DI 28.000 VOTI
    # ──────────────────────────────────────────────

    electoral_authority.close_election()

    start = time.perf_counter()
    signed_results = electoral_authority.tally_votes(candidates)
    end = time.perf_counter()

    add_result(
        results,
        "Scenario universitario: scrutinio 28000 voti",
        1,
        (end - start) * 1000,
        0.0,
        len(serialize(signed_results)),
        "Decifrazione RSA-OAEP e conteggio di tutte le schede"
    )

def save_results(results: list[dict]) -> None:
    """Salva i risultati del benchmark in formato CSV."""
    os.makedirs("outputs", exist_ok=True)

    fieldnames = [
        "operation",
        "repetitions",
        "mean_ms",
        "std_ms",
        "output_size_bytes",
        "notes"
    ]

    with open(OUTPUT_PATH, "w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)


def print_results(results: list[dict]) -> None:
    """Stampa i risultati in forma tabellare semplice."""
    print("\nBenchmark risultati")
    print("-" * 100)

    for row in results:
        print(
            f"{row['operation']:<35} "
            f"mean={row['mean_ms']:>10} ms  "
            f"std={row['std_ms']:>10} ms  "
            f"size={row['output_size_bytes']:>6} bytes  "
            f"{row['notes']}"
        )

    print("-" * 100)
    print(f"Risultati salvati in: {OUTPUT_PATH}")


def main() -> None:
    results = []

    benchmark_crypto_operations(results)
    benchmark_merkle_tree(results)
    benchmark_protocol_operations(results)
    benchmark_university_scenario(results)

    save_results(results)
    print_results(results)


if __name__ == "__main__":
    main()