# Token-2022 Confidential Transfer ZK Audit — Angel Security

**Date**: 2026-04-16
**Target**: solana-program/token-2022 — confidential_transfer extension
**Scope**: processor.rs, verify_proof.rs, proof-extraction (transfer, transfer_with_fee, withdraw), ciphertext-arithmetic, interface/state
**Payout tier**: Up to 25K SOL (loss-of-funds)

---

## Architecture Summary

Confidential transfers split amounts into lo (16-bit) and hi (32-bit) ElGamal ciphertexts. Three ZK proof types per transfer:
1. **CiphertextCommitmentEqualityProof** — source has enough balance (commitment matches ciphertext)
2. **BatchedGroupedCiphertext3HandlesValidityProof** — transfer amount is correctly encrypted under source+destination+auditor keys
3. **BatchedRangeProofU128** — transfer amount and remaining balance are in valid ranges

For fee transfers, add:
4. **PercentageWithCapProof** — fee computed correctly
5. **BatchedGroupedCiphertext2HandlesValidityProof** — fee encrypted correctly under destination+authority keys
6. **BatchedRangeProofU256** — all values in range

Proof verification is delegated to Solana's `zk_elgamal_proof_program` syscalls. The on-chain code only does **context extraction and consistency checks** — it does NOT re-verify the cryptographic proofs.

---

## Findings

### F1: `ApplyPendingBalance` — No Verification of Expected vs Actual Credit Counter

**Severity**: LOW (no fund loss path, but state corruption possible)
**Location**: processor.rs:1196-1249

`ApplyPendingBalance` stores `expected_pending_balance_credit_counter` from user input but never validates it against `actual_pending_balance_credit_counter`. The `actual` is set to whatever `pending_balance_credit_counter` was at apply time, and the `expected` is whatever the caller provides.

The code:
```rust
confidential_transfer_account.actual_pending_balance_credit_counter =
    confidential_transfer_account.pending_balance_credit_counter;
confidential_transfer_account.expected_pending_balance_credit_counter =
    *expected_pending_balance_credit_counter;
```

No check that `expected == actual`. The client is expected to verify this off-chain. If a transfer was silently dropped or duplicated, the mismatch would be recorded but not enforced on-chain. This is **by design** (Solana's approach: on-chain verification of ZK, off-chain monitoring of balance consistency), but it means a malicious RPC could hide transfers from a user who doesn't independently verify.

**Verdict**: Not exploitable for fund loss on-chain. Design choice, not a bug.

---

### F2: `Withdraw` with `amount = 0` Bypasses Ciphertext Arithmetic but Still Passes ZK Check

**Severity**: INFORMATIONAL
**Location**: processor.rs:580-589

```rust
if amount > 0 {
    confidential_transfer_account.available_balance = ciphertext_arithmetic::subtract_from(
        &confidential_transfer_account.available_balance,
        amount,
    )
    .ok_or(TokenError::CiphertextArithmeticFailed)?;
}
```

A zero-amount withdraw still requires valid equality+range proofs (which would prove remaining_balance = available_balance). This is a gas optimization, not a bug. The ZK proofs still enforce consistency.

**Verdict**: No issue.

---

### F3: Range Proof Padding Commitments Not Validated

**Severity**: LOW
**Location**: proof-extraction/transfer.rs:80-85

```rust
let expected_commitments = [
    *new_source_commitment,
    transfer_amount_commitment_lo,
    transfer_amount_commitment_hi,
    // we don't care about the padding commitment, so ignore it
];
```

The range proof context always contains 8 commitments, but only the first 3 are checked (plus 1 padding that's ignored). The remaining 4 commitments in the batched range proof are not validated against anything. This is correct — they're padding for the batched proof format — but it means the range proof is verifying fewer constraints than the batch size implies.

**Verdict**: Correct by design. The ZK proof program already verified all 8 slots; the extraction code just doesn't care about the padding values.

---

### F4: `valid_as_source` Only Checks `approved` — Does Not Check `allow_confidential_credits`

**Severity**: INFORMATIONAL
**Location**: interface/src/extension/confidential_transfer/mod.rs:150-153

```rust
pub fn valid_as_source(&self) -> ProgramResult {
    self.approved()
}
```

Meanwhile `valid_as_destination` checks both `approved` AND `allow_confidential_credits`. This is correct — `allow_confidential_credits` controls receiving, not sending. A source should be able to send regardless of whether it accepts incoming transfers.

**Verdict**: Not a bug.

---

### F5: Fee Calculation Verification in `transfer_with_fee` Uses On-Chain Ristretto Arithmetic That Could Fail Silently

**Severity**: LOW
**Location**: proof-extraction/transfer_with_fee.rs `verify_delta_commitment`

The `verify_delta_commitment` function recomputes the expected delta commitment using on-chain Ristretto point arithmetic:
```rust
let expected_delta_commitment_point =
    ristretto::subtract_ristretto(&scaled_fee_point, &scaled_transfer_amount_point)
        .ok_or(TokenProofExtractionError::CurveArithmetic)?;
```

If any of the `multiply_ristretto` or `subtract_ristretto` operations fail (return `None`), the entire transaction fails. This is safe — it errs on the side of rejection. However, if a valid proof could cause an arithmetic failure (e.g., if the resulting point is the identity), this would be a liveness issue rather than a safety issue.

**Verdict**: No fund loss possible. Worst case: valid transfers get rejected (liveness, not safety).

---

### F6: ElGamal Registry Bypasses Signature Verification for Account Configuration

**Severity**: LOW (potential griefing, not fund theft)
**Location**: processor.rs:248-255

```rust
ElGamalPubkeySource::ElGamalRegistry(elgamal_registry_account) => {
    if elgamal_registry_account.owner != token_account.base.owner {
        return Err(TokenError::OwnerMismatch.into());
    }
}
```

When using ElGamal Registry, the `ConfigureAccount` instruction skips signature verification and only checks that the registry account owner matches the token account owner. The registry account's data is trusted as authoritative. If the registry program has its own vulnerability that allows writing arbitrary ElGamal pubkeys, this could allow configuring a token account with a key the user doesn't control.

However, this requires the registry program itself to be compromised, and the token account owner must match. The user would need to have already interacted with the malicious registry.

**Verdict**: Trust boundary is the registry program. Not a Token-2022 vulnerability.

---

### F7: `closable()` Check Only Verifies Zero Ciphertexts, Not Credit Counter

**Severity**: INFORMATIONAL
**Location**: interface/mod.rs:130-137

```rust
pub fn closable(&self) -> ProgramResult {
    if self.pending_balance_lo == EncryptedBalance::zeroed()
        && self.pending_balance_hi == EncryptedBalance::zeroed()
        && self.available_balance == EncryptedBalance::zeroed()
    {
        Ok(())
    }
}
```

The `closable()` check doesn't verify that `pending_balance_credit_counter == 0`. A closed account could have a non-zero credit counter, but since all balances are zero, this has no practical impact.

**Verdict**: Not a bug. Cosmetic inconsistency at worst.

---

### F8: Ciphertext Arithmetic Returns `None` on Failure — No Distinction Between "Invalid Ciphertext" and "Arithmetic Overflow"

**Severity**: INFORMATIONAL
**Location**: ciphertext-arithmetic/src/lib.rs

All operations (`add`, `subtract`, `add_with_lo_hi`, etc.) return `Option<PodElGamalCiphertext>`. The caller maps `None` to `TokenError::CiphertextArithmeticFailed` with no distinction between:
- Invalid point (non-canonical Ristretto encoding)
- Arithmetic producing identity point (shouldn't happen in valid ElGamal)

This makes debugging harder but doesn't affect security.

**Verdict**: UX issue, not a security issue.

---

## Key Architectural Observation

**The on-chain code does NOT verify ZK proofs.** It extracts proof contexts from the ZK ElGamal proof program's output and checks cross-proof consistency (pubkey matching, commitment matching, bit-length matching). The actual cryptographic verification is done by Solana's built-in `zk_elgamal_proof_program` via syscalls.

This means **the attack surface for fund loss is split**:
1. **Solana ZK proof program** — if it accepts invalid proofs, Token-2022 can't detect this
2. **Token-2022 consistency checks** — if they're bypassed, valid proofs could be replayed with wrong accounts
3. **Ciphertext arithmetic** — if it produces wrong results, balances could be corrupted

All three layers appear sound. The consistency checks are thorough — every pubkey is cross-verified between proofs, every commitment is matched, every bit-length is verified.

---

## Conclusion

**No exploitable loss-of-funds vulnerability found.**

The confidential transfer implementation is well-structured with defense in depth:
- ZK proofs verified by Solana syscalls (layer 1)
- Cross-proof consistency checks in proof-extraction crate (layer 2)
- On-chain balance consistency verification in processor.rs (layer 3)
- All arithmetic uses checked operations (`checked_add`, `checked_sub`, `ok_or`)

The code has been through multiple professional audits (OtterSec, Trail of Bits, Neodyme). The remaining surface is extremely narrow. Finding a novel bug here would require either:
1. A break in Ristretto/ElGamal cryptography itself (not in scope)
2. A bug in Solana's ZK proof program syscalls (not Token-2022 code)
3. A subtle interaction between extensions (confidential + fee + pausable + CPI guard) that hasn't been tested

**Recommendation**: Shift focus to less-audited Solana programs. Token-2022's confidential transfer is hardeneed.