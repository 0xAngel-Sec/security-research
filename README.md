# 0xAngel Security

**Independent security researcher** specializing in Solana protocol audits and responsible disclosure.

## Scope
- Solana on-chain programs (Rust/Anchor)
- DeFi protocols: liquid staking, lending, DEXes, perps
- Smart contract security: arithmetic, reentrancy, access control, state management

## Audits Completed

| Protocol | TVL | Findings | Severity Range | Report |
|----------|-----|----------|---------------|--------|
| Marinade Liquid Staking | $1B+ | 8 | MEDIUM → INFO | [Report](audits/marinade-audit.md) |
| Kamino klend | $1.5B+ | 8 | LOW → INFO | [Report](audits/klend-audit.md) |
| Drift v2 | $500M+ | 8 | LOW → INFO | [Report](audits/drift-audit.md) |
| SPL Token-2022 | Core Solana | 8 | LOW → INFO | [Report](audits/token2022-zk-audit.md) |
| SPL Stake Pool | Core Solana | 8 | MEDIUM → INFO | [Report](audits/stake-pool-audit.md) |
| solana-program/rewards | Anza | 8 | LOW → INFO | [Report](audits/rewards-audit.md) |
| OpenBook v2 | DEX | 0 exploitable | — | *No exploitable findings* |

**Total: 7 protocols, 48 findings, 0 exploitable vulnerabilities**

## Security Advisories Sent

| Protocol | Channel | Status | Advisory |
|----------|---------|--------|----------|
| Marinade | security@marinade.finance | Sent | [Draft](advisories/marinade-advisory.md) |
| Kamino klend | security@kamino.finance | Sent | [Draft](advisories/klend-advisory.md) |
| Drift v2 | GitHub Security Advisory | Pending | [Draft](advisories/drift-advisory.md) |

## Methodology
Full manual code review of every instruction handler, state module, math function, and PDA validation path. No automated scanners. No copy-paste from prior audits.

## Contact
- **Email:** 0xAngel.Security@gmail.com
- **GitHub:** [0xAngel-Sec](https://github.com/0xAngel-Sec)
- **Payout (SOL):** `HUtrZ2RKShak1QFdbQQMajLcRDJ5R4wPRbwrVLPW6phW`
- **Payout (EVM):** `0x37Fd99E737f161671CE5245B2b5Be2FB065f733C`

## Responsible Disclosure
All findings reported privately to protocol security teams before any public disclosure. Coordinated disclosure timelines respected.

---
*No KYC. No middleman platforms. Direct researcher-to-team disclosure only.*
