from src.auth_server import AuthServer
from src.crypto_utils import generate_rsa_keys, serialize, sign
from src.voter import Voter


def expect_rejection(test_name: str, operation) -> None:
    try:
        operation()
    except ValueError:
        print(f"[Test] {test_name}: OK")
        return

    raise AssertionError(f"[Test] {test_name}: FALLITO")


def test_invalid_challenge_signature() -> None:
    auth_server = AuthServer()
    voter = Voter("E_INVALID")
    auth_server.register_voter(voter.voter_id, voter.get_public_key())

    nonce = auth_server.create_challenge(voter.voter_id)
    other_private_key, _ = generate_rsa_keys()
    message = serialize({
        "type": "AUTH_CHALLENGE",
        "voter_id": voter.voter_id,
        "nonce": nonce
    })
    invalid_signature = sign(other_private_key, message)

    expect_rejection(
        "Firma challenge non valida",
        lambda: auth_server.verify_challenge_and_issue_token(
            voter.voter_id,
            voter.generate_token(),
            invalid_signature
        )
    )

    assert voter.voter_id not in auth_server.issued_tokens


def test_challenge_reuse() -> None:
    auth_server = AuthServer()
    voter = Voter("E_REUSE")
    auth_server.register_voter(voter.voter_id, voter.get_public_key())

    nonce = voter.request_auth_challenge(auth_server)
    signature = voter.sign_auth_challenge(nonce)
    token = voter.generate_token()
    auth_server.verify_challenge_and_issue_token(voter.voter_id, token, signature)

    expect_rejection(
        "Riuso challenge",
        lambda: auth_server.verify_challenge_and_issue_token(
            voter.voter_id,
            token,
            signature
        )
    )


def test_second_token_request() -> None:
    auth_server = AuthServer()
    voter = Voter("E_SECOND")
    auth_server.register_voter(voter.voter_id, voter.get_public_key())
    voter.request_signed_token(auth_server)

    expect_rejection(
        "Seconda richiesta token",
        lambda: auth_server.create_challenge(voter.voter_id)
    )


def main() -> None:
    test_invalid_challenge_signature()
    test_challenge_reuse()
    test_second_token_request()


if __name__ == "__main__":
    main()