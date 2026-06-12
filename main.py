# main.py
import sys
from pathlib import Path

from src.election_simulation import ElectionSimulation


def print_separator() -> None:
    print("-" * 70)


def main() -> None:
    """
    Esegue una simulazione completa del protocollo.

    Questo script serve come esempio di esecuzione da mostrare nel WP4:
    registrazione, voto, chiusura, verifica individuale, scrutinio
    e verifica universale.
    """

    candidates = [
        "Candidato A",
        "Candidato B",
        "Candidato C"
    ]

    voter_ids = [
        "E01",
        "E02",
        "E03",
        "E04",
        "E05"
    ]

    votes = {
        "E01": "Candidato A",
        "E02": "Candidato B",
        "E03": "Candidato A",
        "E04": "Candidato C",
        "E05": "Candidato A"
    }

    print("[Setup] Inizializzazione simulazione")
    simulation = ElectionSimulation(candidates)

    print("[SA] Registrazione elettori aventi diritto")
    simulation.register_voters(voter_ids)

    print_separator()

    print("[Voto] Avvio fase di voto")
    for voter_id, vote in votes.items():
        voter = simulation.get_voter_by_id(voter_id)

        print(f"[Elettore {voter_id}] Richiesta challenge al Sistema di Autenticazione")
        nonce = voter.request_auth_challenge(simulation.auth_server)
        print(f"[SA] Challenge generato per {voter_id} ({nonce[:12]}...)")

        voter.sign_auth_challenge(nonce)
        print(f"[Elettore {voter_id}] Challenge firmato")

        voter.submit_auth_challenge(simulation.auth_server)
        print("[SA] Challenge verificato: token emesso")
        print(f"[Elettore {voter_id}] Cifratura voto con RSA-OAEP")
        print(f"[AE] Verifica token e registrazione scheda")

        receipt = simulation.cast_vote(voter, vote)

        print(f"[AE] Ricevuta generata per {voter_id}")
        print(f"     index = {receipt['index']}")
        print(f"     id    = {receipt['id']}")

    print_separator()

    print("[AE] Chiusura urne")
    close_message = simulation.electoral_authority.close_election()
    simulation.close_message = close_message

    print("[AE] Messaggio di chiusura pubblicato")
    print(f"     root_B      = {close_message['root_B']}")
    print(f"     m           = {close_message['m']}")
    print(f"     sigma_close = {close_message['sigma_close'][:40]}...")

    print_separator()

    print("[Verifica individuale] Controllo ricevute e inclusione nel Bulletin Board chiuso")
    individual_checks = simulation.verify_individual_checks()

    for voter_id, result in individual_checks.items():
        status = "OK" if result else "FALLITA"
        print(f"[Elettore {voter_id}] Verifica individuale: {status}")

    print_separator()

    print("[AE] Scrutinio")
    signed_results = simulation.electoral_authority.tally_votes(candidates)
    simulation.signed_results = signed_results

    results = signed_results["results"]

    print("[AE] Risultato finale firmato")
    for key, value in results.items():
        if key != "root_B":
            print(f"     {key}: {value}")

    print(f"     root_B: {results['root_B']}")
    print(f"     sigma_R: {signed_results['sigma_r'][:40]}...")

    print_separator()

    print("[Verificatore Pubblico] Verifica universale")
    universal_check = simulation.verify_universal_check()

    status = "OK" if universal_check else "FALLITA"
    print(f"[Verificatore Pubblico] Verifica universale: {status}")

    print_separator()

    print("[Bulletin Board] Voci pubblicate")
    for index, entry in enumerate(simulation.bulletin_board.get_entries()):
        print(f"Voce {index}:")
        print(f"     id         = {entry['id']}")
        print(f"     ciphertext = {entry['ciphertext'][:40]}...")
        print(f"     signature  = {entry['signature'][:40]}...")

    print_separator()

    print("[Fine simulazione]")


if __name__ == "__main__":
    output_dir = Path("outputs")
    output_dir.mkdir(exist_ok=True)

    output_file = output_dir / "sample_run.txt"

    with output_file.open("w", encoding="utf-8") as file:
        original_stdout = sys.stdout
        sys.stdout = file

        try:
            main()
        finally:
            sys.stdout = original_stdout