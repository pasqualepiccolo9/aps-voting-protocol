# src/election_simulation.py

from typing import Optional

from src.auth_server import AuthServer
from src.bulletin_board import BulletinBoard
from src.electoral_authority import ElectoralAuthority
from src.verifier import PublicVerifier
from src.voter import Voter


class ElectionSimulation:
    """
    Simulazione completa del protocollo di voto elettronico.

    Questa classe collega tutti gli attori principali:
    - Sistema di Autenticazione (SA);
    - Autorità Elettorale (AE);
    - Elettori;
    - Bulletin Board;
    - Verificatore Pubblico.

    L'obiettivo è simulare il flusso progettato nel WP2:
    registrazione, autenticazione, emissione token, voto cifrato,
    pubblicazione sul Bulletin Board, scrutinio e verifica universale.
    """

    def __init__(self, candidates: list[str]):
        if not candidates:
            raise ValueError("La simulazione richiede almeno un candidato.")

        self.candidates = candidates

        self.bulletin_board = BulletinBoard()
        self.auth_server = AuthServer()

        self.electoral_authority = ElectoralAuthority(
            auth_server_public_key=self.auth_server.get_public_key(),
            bulletin_board=self.bulletin_board
        )

        self.public_verifier = PublicVerifier(
            ae_signing_public_key=self.electoral_authority.get_signing_public_key()
        )

        self.voters: list[Voter] = []
        self.receipts: list[dict] = []

        self.close_message: Optional[dict] = None
        self.signed_results: Optional[dict] = None

    # ──────────────────────────────────────────────
    # REGISTRAZIONE ELETTORI
    # ──────────────────────────────────────────────

    def register_voters(self, voter_ids: list[str]) -> None:
        """
        Registra gli elettori presso il Sistema di Autenticazione.

        Ogni elettore genera la propria coppia di chiavi.
        Il SA registra l'identificativo reale dell'elettore e la sua chiave pubblica.
        """
        for voter_id in voter_ids:
            voter = Voter(voter_id)

            self.auth_server.register_voter(
                voter_id=voter.voter_id,
                voter_public_key=voter.get_public_key()
            )

            self.voters.append(voter)

    def get_voter_by_id(self, voter_id: str) -> Voter:
        """Restituisce un elettore registrato dato il suo identificativo."""
        for voter in self.voters:
            if voter.voter_id == voter_id:
                return voter

        raise ValueError(f"Elettore non registrato: {voter_id}")

    # ──────────────────────────────────────────────
    # FASE DI VOTO
    # ──────────────────────────────────────────────

    def authenticate_voter(self, voter: Voter) -> dict:
        """Autentica l'elettore tramite challenge-response ed emette il token."""
        return voter.request_signed_token(self.auth_server)

    def cast_vote(self, voter: Voter, vote: str) -> dict:
        """
        Simula il voto di un singolo elettore.

        Passaggi:
        1. l'elettore completa il challenge-response con il SA;
        2. il SA emette il token firmato;
        3. l'elettore cifra il voto con la chiave pubblica dell'AE;
        4. l'AE verifica il token, registra la scheda e produce una ricevuta;
        5. l'elettore conserva la ricevuta.
        """
        if vote not in self.candidates:
            raise ValueError("Candidato non valido.")

        if voter.signed_token is None:
            self.authenticate_voter(voter)

        ballot_packet = voter.prepare_ballot_packet(
            vote=vote,
            ae_public_key=self.electoral_authority.get_encryption_public_key()
        )

        receipt = self.electoral_authority.submit_ballot(ballot_packet)

        voter.store_receipt(receipt)
        self.receipts.append(receipt)

        return receipt

    def cast_votes(self, votes: dict[str, str]) -> None:
        """
        Simula il voto di più elettori.

        votes è un dizionario del tipo:
        {
            "E01": "Candidato A",
            "E02": "Candidato B"
        }
        """
        for voter_id, vote in votes.items():
            voter = self.get_voter_by_id(voter_id)
            self.cast_vote(voter, vote)

    # ──────────────────────────────────────────────
    # VERIFICA INDIVIDUALE
    # ──────────────────────────────────────────────

    def verify_individual_checks(self) -> dict[str, bool]:
        """
        Esegue la verifica individuale per ogni elettore registrato.

        Ogni elettore controlla:
        - che la propria ricevuta corrisponda alla voce pubblicata;
        - che la firma dell'AE sia valida;
        - che la voce sia inclusa nel Merkle Tree.
        """
        checks = {}

        for voter in self.voters:
            if voter.receipt is None:
                checks[voter.voter_id] = False
                continue

            official_root_hex = None
            if self.close_message is not None:
                official_root_hex = self.close_message["root_B"]

            is_valid = voter.verify_individual_inclusion(
                bulletin_board=self.bulletin_board,
                ae_public_key=self.electoral_authority.get_signing_public_key(),
                official_root_hex=official_root_hex
            )

            checks[voter.voter_id] = is_valid

        return checks

    # ──────────────────────────────────────────────
    # CHIUSURA E SCRUTINIO
    # ──────────────────────────────────────────────

    def close_and_tally(self) -> dict:
        """
        Chiude le urne ed esegue lo scrutinio.

        L'AE pubblica:
        - il messaggio di chiusura firmato;
        - il risultato finale firmato.
        """
        self.close_message = self.electoral_authority.close_election()
        self.signed_results = self.electoral_authority.tally_votes(self.candidates)

        return {
            "close_message": self.close_message,
            "signed_results": self.signed_results
        }

    # ──────────────────────────────────────────────
    # VERIFICA UNIVERSALE
    # ──────────────────────────────────────────────

    def verify_universal_check(self) -> bool:
        """
        Esegue la verifica universale pubblica.

        Controlla:
        - Bulletin Board;
        - firme AE sulle singole voci;
        - Merkle Tree;
        - firma di chiusura;
        - firma del risultato;
        - coerenza tra numero di schede e risultato.
        """
        if self.close_message is None or self.signed_results is None:
            return False

        return self.public_verifier.verify_universal(
            bulletin_board=self.bulletin_board,
            close_message=self.close_message,
            signed_results=self.signed_results
        )

    # ──────────────────────────────────────────────
    # ESECUZIONE COMPLETA
    # ──────────────────────────────────────────────

    def run(self, votes: dict[str, str]) -> dict:
        """
        Esegue una simulazione completa.

        Il dizionario votes definisce quali elettori votano e quale preferenza scelgono.
        """
        self.cast_votes(votes)

        final_data = self.close_and_tally()
        individual_checks = self.verify_individual_checks()
        universal_check = self.verify_universal_check()

        return {
            "individual_checks": individual_checks,
            "close_message": final_data["close_message"],
            "signed_results": final_data["signed_results"],
            "universal_check": universal_check,
            "bulletin_board_root": self.bulletin_board.get_merkle_root_hex(),
            "published_entries": self.bulletin_board.get_entries()
        }
