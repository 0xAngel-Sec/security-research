# Security Advisory Draft — Marinade Liquid Staking

**To:** security@marinade.finance
**From:** 0xAngel.Security@gmail.com
**Identity:** Independent security researcher, DOB April 12 2000
**Date:** 2026-04-17

---

Subject: [Security Advisory] Marinade Liquid Staking — Unchecked Subtraction in on_transfer_from_reserve (MEDIUM) + Additional Findings

Hi Marinade Security Team,

I'm an independent security researcher. I've completed a deep audit of the Marinade liquid-staking-program (51 Rust files, ~15K+ lines) and identified several findings, including one MEDIUM-severity issue that I believe warrants attention.

## F1: Unchecked Subtraction in on_transfer_from_reserve (MEDIUM)

**File:** `instructions/crank/stake_reserve.rs`
**Function:** `on_transfer_from_reserve`

The `reserve_amount -= transferred_lamports` subtraction uses the primitive `-` operator (wrapping subtraction) rather than `.checked_sub()`. While all current call sites validate that `transferred_lamports <= reserve_amount` before invoking, the function itself does not enforce this invariant. If a future code path calls `on_transfer_from_reserve` without the upstream check, this would silently wrap around, corrupting the reserve balance.

**Impact:** Latent footgun — correct today but fragile under future code changes. A wrapping underflow could corrupt the staking pool balance.

**Recommendation:** Replace `reserve_amount -= transferred_lamports` with `reserve_amount.checked_sub(transferred_lamports)?` to enforce the invariant at the operation level.

## F2: max_stake_moved_per_epoch Has No Upper Bound (LOW)

**File:** `state/stake_delta.rs`

The `max_stake_moved_per_epoch` parameter can be set to any value including 100% of stake, enabling rapid validator movement in a single epoch. While admin-restricted, this represents a single point of failure if admin keys are compromised.

**Recommendation:** Consider adding a sensible upper bound (e.g., 50% per epoch) to limit blast radius of compromised admin keys.

## F3: remove_liquidity Withdraws Before Burning LP Tokens (LOW)

**File:** `instructions/liq_pool/remove_liquidity.rs`

The withdrawal of SOL occurs before the LP token burn in the same transaction. While Solana's atomic transaction model ensures safety (if burn fails, entire tx reverts), this ordering is unusual and could confuse auditors or integrators.

**Recommendation:** Consider reordering to burn-first-then-withdraw for clarity and defense-in-depth.

## F4: liquid_unstake Fee Rounding Truncation (LOW)

**File:** `instructions/liq_pool/liquid_unstake.rs`

Fee calculations consistently use floor division, always truncating in the protocol's favor. Systematic value leakage from withdrawers to remaining holders.

**Recommendation:** Document the rounding direction explicitly in code comments.

## F5: stake_delta Emergency Cooling Down Complexity (LOW)

**File:** `state/stake_delta.rs`

The emergency cooling-down state machine has multiple code paths that set `stake_delta.emergency` and different validations for `min_stake_delta` vs `stake_delta.target`. Correct but subtle — future modifications could easily introduce inconsistencies.

**Recommendation:** Consider consolidating emergency state transitions into a single function with explicit state machine documentation.

---

I'm reporting these responsibly and will not disclose them publicly until you've had time to assess and address them. I'd appreciate confirmation of receipt and would welcome discussion of any potential bounty consideration.

Payout preference: SOL to HUtrZ2RKShak1QFdbQQMajLcRDJ5R4wPRbwrVLPW6phW

Best regards,
0xAngel.Security