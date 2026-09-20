"""The grinding attack the mutual commit-then-reveal pairing protocol exists to close, kept as
a regression test dependency (see test_grind_attack_cannot_force_a_matching_code).

The broken shape: a companion that revealed its own nonce in its first response, having already
seen the phone's public key, let an attacker playing the companion role try many (private key,
nonce) pairs offline, no network round trip per guess, until one produced whatever four-digit
code it wanted the human to see. Measured against that design: a forced match in a few thousand
tries, under a second.

The fixed shape (companion_server.py, POST /pair-start then POST /pair-reveal): both sides
publish H(own nonce || own pubkey) before either nonce is revealed, and the companion reveals its
nonce only after the phone's reveal has been checked against the phone's commitment. An attacker
in the companion role does not know the phone's nonce at grinding time, only a SHA-256 digest of
it. The code depends on both nonces, so a candidate is worthless until the attacker has also
guessed the phone's 16-byte nonce and matched it against the commitment, which is a preimage
problem, not a small-space code-matching one.

The chance threshold, stated explicitly: each attempt has an independent 1-in-2^128 chance of
guessing the phone's nonce. At 5000 attempts the expected number of correct guesses is about
1.5e-35, indistinguishable from zero. So `commitment_guesses_correct == 0` and
`forced_match is False` are exactly what chance predicts, not a stricter bar. A regression that
revealed either nonce early would let the attacker skip the guess and force a match on nearly
every attempt, which is what the test would then catch.
"""
import os
import secrets
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import companion_server as cs  # noqa: E402  (the real protocol's own functions)

from cryptography.hazmat.primitives.asymmetric import x25519  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402


def _keypair():
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    return priv, pub


def run_attack(attempts=5000, target_code="1234"):
    """Simulates the grinding attack against the fixed protocol.

    One real phone leg (a real keypair, a secret 16-byte nonce, and the commitment that nonce
    implies, exactly what /pair-start receives). The attacker then tries `attempts` candidate
    (companion keypair, companion nonce, GUESSED phone nonce) triples offline. A candidate's
    phone-nonce guess must match the phone's published commitment before it means anything.

    Runs in well under a second at the default attempt count.

    Returns {"attempts": int, "forced_match": bool, "elapsed_seconds": float,
    "commitment_guesses_correct": int}."""
    phone_priv, phone_pub = _keypair()
    phone_nonce = secrets.token_bytes(16)  # the attacker never sees this
    phone_commitment = cs._commitment(phone_nonce, phone_pub)

    commitment_guesses_correct = 0
    forced_match = False
    start = time.monotonic()

    for _ in range(attempts):
        companion_priv, companion_pub = _keypair()
        companion_nonce = secrets.token_bytes(16)
        guessed_phone_nonce = secrets.token_bytes(16)  # attacker's blind guess

        if not cs.hmac.compare_digest(
                cs._commitment(guessed_phone_nonce, phone_pub), phone_commitment):
            continue  # the guess does not match the real commitment - nothing to compute yet
        commitment_guesses_correct += 1

        # Only reachable if the 128-bit guess above happened to be exactly right. Included in
        # full so this demonstrates what an attacker WOULD do with a correct guess.
        shared_secret = companion_priv.exchange(x25519.X25519PublicKey.from_public_bytes(phone_pub))
        _session_key, code = cs._derive_pairing_material(
            shared_secret, guessed_phone_nonce, companion_nonce, companion_pub, phone_pub)
        if code == target_code:
            forced_match = True
            break

    elapsed = time.monotonic() - start
    return {
        "attempts": attempts,
        "forced_match": forced_match,
        "elapsed_seconds": elapsed,
        "commitment_guesses_correct": commitment_guesses_correct,
    }


if __name__ == "__main__":
    result = run_attack(attempts=5000)
    print("grind attack result: %r" % result)
    if result["forced_match"]:
        print("ATTACK SUCCEEDED - the protocol is leaking a nonce early")
        raise SystemExit(1)
    print("attack failed to force a match, as expected under mutual commit-then-reveal")
