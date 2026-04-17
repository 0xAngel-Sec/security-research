# Security Advisory Draft — Kamino klend

**To:** security@kamino.finance
**Via:** Direct email (from on-chain security_txt! macro)
**From:** 0xAngel.Security@gmail.com
**Identity:** Independent security researcher, DOB April 12 2000
**Date:** 2026-04-17

---

Subject: [Security Advisory] Kamino klend — Elevation Group Zero-Default Bypass + Additional Findings

Hi Kamino Security Team,

I'm an independent security researcher. I've completed a deep audit of the Kamino klend lending protocol (13 core files, ~15K+ lines) and identified several findings I'd like to responsibly disclose.

## F1: Elevation Group max_liquidation_bonus_bps Zero Default Bypasses Cap (LOW)

**File:** `state/reserve.rs`, `lending_market/lending_checks.rs`

When `max_liquidation_bonus_bps == 0`, the elevation group liquidation bonus cap check is skipped entirely (interpreted as "not set"). This means an elevation group that intends to restrict liquidation bonuses would silently allow unrestricted bonuses if the value is left at the default zero.

**Impact:** Governance footgun. A misconfigured elevation group could allow larger liquidation bonuses than intended. Not directly exploitable for fund loss, but could enable more aggressive liquidation behavior than governance intended.

**Recommendation:** Use a sentinel value (e.g., `u16::MAX`) for "not set" instead of `0`, or add an explicit `is_set` boolean flag for `max_liquidation_bonus_bps`.

## F2: forgive_debt Uses Primitive Subtraction Without Checked Math (LOW)

**File:** `handlers/handler_socialize_loss.rs`, `state/obligation.rs`

The `forgive_debt` function uses primitive `-=` subtraction on `borrowed_amount_sf` without checked arithmetic. While all callers cap the forgiven amount via `min(liquidity_amount, borrowed_amount)`, the primitive operation itself doesn't enforce this invariant.

**Impact:** If a future code path calls `forgive_debt` without the upstream `min()` cap, it could underflow. Not exploitable at current call sites.

**Recommendation:** Replace `borrowed_amount_sf -= forgave_amount_sf` with `.checked_sub()` for defense-in-depth.

## F3: Socialize Loss Deprecates Reserve With Inconsistent Accounting (LOW)

**File:** `state/reserve.rs`, `handlers/handler_socialize_loss.rs`

After `socialize_loss`, the reserve is marked deprecated and `forgive_debt` reduces `borrowed_amount_sf` but does not adjust `total_available_amount`. This creates an inconsistency where the exchange rate calculation no longer reflects the true state.

**Impact:** Known design trade-off. Exchange rate distortion in deprecated reserves. Not exploitable for direct fund loss since deprecated reserves cannot accept new borrows.

**Recommendation:** Document this accounting decision explicitly or add a post-deprecation exchange rate freeze.

## F7: Elevation Group new_loans_disabled Not Checked on Same-Reserve Rollover (LOW)

**File:** `handlers/` (rollover instruction path)

When `new_loans_disabled` is set for an elevation group, new borrows are blocked. However, same-reserve rollovers (extending a fixed-term borrow) bypass this check, allowing term extensions even when new lending is disabled.

**Impact:** Could allow borrowers to extend positions that governance intended to wind down. May be intentional design (rolling over existing position vs creating new one).

**Recommendation:** Clarify whether rollovers should respect `new_loans_disabled`. If they should, add the elevation group check to the rollover path.

---

I'm reporting these responsibly and will not disclose publicly until you've had time to assess. I'd appreciate confirmation of receipt and discussion of any potential bounty consideration.

Payout preference: SOL to HUtrZ2RKShak1QFdbQQMajLcRDJ5R4wPRbwrVLPW6phW

Best regards,
0xAngel.Security