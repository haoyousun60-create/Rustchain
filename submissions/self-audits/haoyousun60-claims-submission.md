# Self-Audit: node/claims_submission.py

## Wallet
RTC4642c5ee8467f61ed91b5775b0eeba984dd776ba

## Module reviewed
- Path: node/claims_submission.py
- Commit: cb17137e
- Lines reviewed: whole-file

## Deliverable: 3 specific findings

1. **Signature Verification Bypass via `skip_signature_verify` Parameter**
   - Severity: critical
   - Location: node/claims_submission.py:220-260 (`submit_claim` function signature and line ~255)
   - Description: The `submit_claim()` function accepts a `skip_signature_verify: bool = False` parameter that completely bypasses Ed25519 signature verification when set to `True`. While the default is `False`, any caller can pass `True` — meaning a single misconfigured route handler, a debugging leftover, or a compromised calling module allows an attacker to submit fraudulent reward claims with arbitrary wallet addresses without any cryptographic proof of ownership. The function signature makes this bypass a first-class API surface, not an accidental escape hatch.
   - Reproduction: Call `submit_claim(..., skip_signature_verify=True)` with any miner_id, epoch, and attacker-controlled wallet_address. The claim will be accepted and recorded in the database with status 'pending' regardless of whether the signature is valid.

2. **Replay Attack: No Timestamp Window Validation on Signed Claims**
   - Severity: high
   - Location: node/claims_submission.py:248-258 (signature verification block in `submit_claim`)
   - Description: The signature payload includes a `timestamp` field (generated from `current_ts`), but the verification logic never checks whether this timestamp falls within an acceptable time window. An attacker who captures a single valid signed claim (e.g., from network traffic or database inspection) can replay it indefinitely — the signature will always verify successfully because there is no expiry check. Combined with the `UNIQUE(miner_id, epoch)` constraint, an attacker could front-run the legitimate miner's claim for a given epoch by replaying a previously captured signature from a different epoch (if the payload structure is predictable) or by timing submission before the legitimate user.
   - Reproduction: (1) Submit a valid claim with a real Ed25519 signature at time T. (2) Capture the signature and payload. (3) At time T+86400 (or any future time), resubmit the same payload/signature — the `validate_claim_signature` function will return `(True, None)` because no timestamp window is enforced.

3. **Wallet Address Validation Inconsistency Enables Cross-Module Bypass**
   - Severity: medium
   - Location: node/claims_submission.py:81-92 (`validate_wallet_address_format`) vs node/payout_preflight.py:62-65 (`validate_wallet_transfer_signed`)
   - Description: `claims_submission.py` validates wallet addresses with pattern `^RTC[a-zA-Z0-9]{20,40}$` (accepting 23–43 character addresses), while `payout_preflight.py` enforces exactly `len(address) == 43` with `address.startswith("RTC")`. This means a 24-character address like `RTC1234567890123456789012` passes claims validation but would be rejected by the payout preflight check. An attacker could submit claims with a short-valid-but-payout-invalid address, creating claims that can never be settled — effectively locking reward funds in a pending state and causing a denial-of-service against the settlement pipeline. Alternatively, if a future code path relaxes payout validation, these mismatched addresses become a fund-loss vector.
   - Reproduction: Submit a claim with wallet_address `RTCabcdefghijklmnopqrst` (23 chars). It passes `validate_wallet_address_format()` (regex matches 20-40 alphanumerics after RTC). Then attempt to process the payout via `validate_wallet_transfer_signed()` — it fails with `invalid_to_address_format` because length ≠ 43.

## Known failures of this audit
- Did not check the HTTP route handlers that call `submit_claim()` to verify whether `skip_signature_verify` is ever passed as `True` in production code paths — the function signature alone makes it a risk surface
- Did not analyze `claims_eligibility.py` (imported dependency) for eligibility check bypasses — focused only on the claims_submission module
- Did not test with actual Ed25519 keypairs to verify the signature verification logic handles edge cases (malleable signatures, non-canonical encodings) — relied on PyNaCl's documented behavior
- Low confidence on whether the replay attack (finding #2) is exploitable in practice without knowing the network-level exposure of the claim submission endpoint

## Confidence
- Overall confidence: 0.78
- Per-finding confidence: [0.92, 0.75, 0.68]

## What I would test next
- Trace all callers of `submit_claim()` across the codebase to determine if `skip_signature_verify=True` is ever passed in production route handlers
- Analyze the HTTP API layer to determine if claim submission endpoints are publicly accessible without authentication, which would make the replay attack (finding #2) directly exploitable
- Check whether `claims_eligibility.py` performs its own independent wallet address validation or trusts the caller's validation, to determine if the inconsistency in finding #3 has downstream impact
