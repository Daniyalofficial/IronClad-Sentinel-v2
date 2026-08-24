# Pricing & Go-To-Market Notes

This is a suggested starting model, not a locked-in decision -- adjust
based on real conversations with prospects. The point of writing it down
is to make the "how do I actually turn this code into revenue" step
mechanical rather than something you have to invent from scratch later.

## Positioning

**One sentence:** "The only SAST/secrets/SBOM scanner your security
team will actually approve for the crown-jewel repo, because it never
sends a single byte of your code anywhere."

This targets a specific, real objection enterprise security teams raise
against Snyk/Semgrep Cloud/etc: those tools require sending source (or
at minimum diffs/metadata) to a third-party's servers. Regulated
industries (banking, defense, healthcare, government contractors) and
security-mature companies in general have procurement policies that
make that a multi-month legal review at best, an instant no at worst.
IronClad Sentinel sidesteps the entire objection structurally, not just
contractually ("we promise not to look at your data") -- there is
literally no code path that sends data out.

## Target buyer

- Primary champion: Head of AppSec / Security Engineering Lead / Staff
  Security Engineer.
- Economic buyer: CISO or VP Engineering (budget owner).
- Company profile: 200-5,000 employees, has a dedicated security
  function, operates in a regulated or IP-sensitive industry (fintech,
  healthtech, defense/govtech, legal tech, crypto/web3), OR any company
  that has had a "we can't approve this SaaS tool through vendor
  security review" experience with a competitor.

## Suggested tiers

| Tier | Price (illustrative) | Seats | Engines | Support |
|---|---|---|---|---|
| **Trial** | Free, 30 days | Unlimited | AST + rule-engine + secrets only | Community/docs only |
| **Standard** | $4,000/yr | Up to 15 developers | All 6 engines | Email, 2 business-day SLA |
| **Professional** | $15,000/yr | Up to 75 developers | All 6 engines + priority rule-pack updates | Email + quarterly rule-pack refresh call |
| **Enterprise** | $40,000+/yr (custom) | Unlimited | All 6 engines + custom rule-pack authoring engagement + PyInstaller binary builds signed with customer-specific cert | Dedicated Slack channel, SLA, contractual data-handling addendum (trivial to sign since there IS no data handling) |

Price anchor logic: this replaces (or sits alongside, cheaper, as the
"regulated repos" carve-out) tools that commonly run $20-150+ per
developer per year at enterprise scale. Pricing per-seat-unlimited
rather than strictly per-seat metered removes a procurement friction
point (no usage audits/true-ups needed since there's no telemetry to
measure usage with anyway -- lean into that as a feature, not a
limitation).

## Sales motion

1. **Land via the free trial.** The trial tier is deliberately
   full-strength on the AST + rule-engine + secrets detectors (the
   engines that produce the most "wow, it found that?" moments in a
   first demo) so a security engineer can self-serve an evaluation
   against a real (or representative) repo without any sales
   conversation.
2. **The upgrade trigger is organic**, not artificial: dependency/IaC/
   license-compliance scanning and CI report formats (SARIF/JUnit) are
   licensed, so the natural next step after "this looks useful in
   trial" is "now let's actually wire it into CI," which is exactly
   when a license is needed.
3. **Procurement acceleration kit**: prepare a one-page "security
   architecture" document (this repo's README section on offline-only
   architecture, adapted) to hand directly to the prospect's own
   vendor-security review team. Removing their biggest objection
   pre-emptively is the single highest-leverage sales asset for this
   category of product.
4. **Land-and-expand**: start with one team's repo (Standard tier),
   expand to Enterprise once security/platform leadership sees the
   reports and wants org-wide rollout + custom rule packs for their
   internal frameworks.

## What "custom rule pack authoring" (an Enterprise upsell) looks like

Large customers often have internal frameworks/ORMs/auth libraries that
generic rules don't know about (e.g. "our internal `InternalDB.raw()`
method is just as dangerous as `cursor.execute()` with string
concatenation, but no generic tool knows that method exists"). Because
the rule engine is a documented YAML DSL (`ironclad/rules/schema.py`),
writing 10-20 bespoke rules for a customer's internal APIs is a
half-day to two-day paid engagement per customer -- pure margin, uses
the same engine, and deepens lock-in (their custom rules only run
inside IronClad Sentinel).

## Objection handling cheat sheet

- *"How do we know it doesn't phone home?"* -- Point to the fact that
  even license verification (`ironclad/licensing/keygen.py`) is a local
  Ed25519 signature check with a bundled public key. Offer to let their
  team run it fully network-isolated (`iptables` deny-all / air-gapped
  VM) as part of evaluation -- it will work identically, which is
  itself the proof.
- *"Your vulnerability DB isn't live, how current is it?"* -- Be
  upfront: it's a periodically-updated bundled snapshot, refreshed with
  each product release, exactly like how a customer's own internal
  tools would need to be updated. Offer a documented update cadence
  (e.g. monthly release with refreshed `vuln_db.json`) as part of a
  paid support tier. This is a feature-vs-tradeoff conversation, not a
  weakness to hide.
- *"Why not just use Semgrep OSS / Trivy / Bandit separately?"* -- Those
  are excellent standalone engines but this product's value is the
  unification: one config file, one report format set (SARIF/JUnit/etc
  all normalized to a single finding schema), one CI job, one license
  relationship, and consistent baseline/fingerprinting logic across ALL
  finding types instead of stitching together 4 separate tools' output
  formats yourself.
