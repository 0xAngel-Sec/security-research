# Security Advisory Draft — Drift v2

**To:** GitHub Security Advisory (https://github.com/drift-labs/protocol-v2/security/advisories/new)
**Note:** No direct email found. On-chain security_txt! points to 404 docs page. Use GitHub advisory or Discord (discord.gg/95kByNnDy5)
**From:** 0xAngel.Security@gmail.com
**Identity:** Independent security researcher, DOB April 12 2000
**Date:** 2026-04-17

---

Subject: [Security Advisory] Drift v2 — AMM Spread Calculation + Additional Findings

Hi Drift Security Team,

I'm an independent security researcher. I've completed a deep audit of the Drift v2 protocol (13 core files, ~12K+ lines) focusing on AMM, insurance fund, liquidation, orders, and PnL modules. I'd like to responsibly disclose the following findings.

## F1: AMM Spread Calculation Uses Stale Reserve Values (LOW)

**File:** `math/amm.rs`, `math/amm_spread.rs`

The spread calculation between `reserve1` and `reserve2` can use values from different update slots, allowing a momentary discrepancy where the spread is calculated on slightly stale data. In high-volatility scenarios, this could lead to slightly wider or narrower spreads than intended.

**Impact:** Bounded by the slot difference. Not directly exploitable for fund loss since the discrepancy is small and MEV searchers would arbitrage it away before exploitation.

**Recommendation:** Consider adding a staleness check in spread calculation that rejects or flags if the reserve values are from different slots.

## F2: Insurance Fund Withdrawal Ordering (LOW)

**File:** `controller/insurance.rs`

Insurance fund withdrawals process in insertion order rather than by priority. If the fund is insufficient, earlier withdrawals are fully satisfied while later ones are partially or not at all.

**Impact:** Not directly exploitable (withdrawals require authority), but creates potential fairness concern for large-scale withdrawal events.

**Recommendation:** Consider pro-rata distribution when the insurance fund is insufficient to cover all pending withdrawals.

## F3: Liquidation Penalty Rounding Direction (LOW)

**File:** `math/liquidation.rs`

Penalty calculations use consistent ceiling rounding, always rounding in the protocol's favor. This is standard DeFi practice but creates systematic value leakage from liquidated users.

**Impact:** Bounded, predictable, and standard across DeFi protocols. Not exploitable but worth documenting explicitly.

**Recommendation:** Document rounding direction explicitly in liquidation math comments.

## F4: Order Expiry Slot Comparison Ambiguity (LOW)

**File:** `controller/orders.rs`

Order expiry uses direct slot comparison without explicitly handling the case where `current_slot == order.expiry_slot`. Some code paths treat `==` as expired, others as active.

**Impact:** Potential for off-by-one slot behavior at exact expiry. Not exploitable for fund loss (orders can be cancelled either way), but could cause unexpected order cancellation.

**Recommendation:** Add explicit `<=` vs `<` comparison standard and document the intended behavior at exact expiry.

## F5: AMM JIT Quote Price Impact Not Capped (LOW)

**File:** `math/amm_jit.rs`

The JIT (Just-In-Time) liquidity quote doesn't cap price impact, allowing large swaps to move the AMM price significantly in a single transaction. While this is by design for a perps protocol (price discovery), it creates potential for sandwich attacks on large JIT-provided liquidity.

**Impact:** Known design trade-off for perps protocols. MEV protection is handled at the keeper level.

**Recommendation:** Consider adding an optional `max_price_impact_bps` parameter for JIT quotes as a defense-in-depth measure.

---

I'm reporting these responsibly and will not disclose publicly until you've assessed them. I'd appreciate confirmation of receipt and discussion of potential bounty consideration.

Payout preference: SOL to HUtrZ2RKShak1QFdbQQMajLcRDJ5R4wPRbwrVLPW6phW

Best regards,
0xAngel.Security