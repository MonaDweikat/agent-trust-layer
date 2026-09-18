/**
 * Shared setup for the demo scenarios: a trusted issuer, a trusted voucher,
 * and the "purchase" policy every scenario evaluates a request against.
 */

import { generateIdentity } from "../src/identity/index.js";
import { definePolicy, requireCredential, requireVouches } from "../src/policy/index.js";
import { requireAuthorityScope } from "./policies.js";
import type { PolicyDecision } from "../src/policy/index.js";

export const issuer = generateIdentity(); // "Acme Trust Registry"
export const voucher = generateIdentity(); // "Longtime Partner Agent"

export const TRUSTED_ISSUERS = [issuer.did];
export const TRUSTED_VOUCHERS = [voucher.did];

export const purchasePolicy = definePolicy("purchase", [
  requireAuthorityScope("purchasing", TRUSTED_ISSUERS),
  requireCredential(
    "ActionHistoryCredential",
    "holds an ActionHistoryCredential with successRate >= 0.9",
    (subj) => (subj.successRate as number) >= 0.9,
  ),
  requireVouches(1, TRUSTED_VOUCHERS),
]);

export function printHeader(title: string): void {
  console.log(`\n=== ${title} ===\n`);
}

export function printDecision(requesterName: string, decision: PolicyDecision, extra?: string): void {
  const icon = decision.decision === "accept" ? "✅ ACCEPT" : "❌ REFUSE";
  console.log(`${icon} — task request from ${requesterName}`);
  if (extra) console.log(`  ${extra}`);
  for (const rule of decision.trace) {
    console.log(`  ${rule.passed ? "✓" : "✗"} ${rule.description}`);
  }
  console.log();
}
