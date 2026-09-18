import { generateIdentity } from "../src/identity/index.js";
import { issueCredential } from "../src/credentials/index.js";
import { verifyCredential, type VerifiedCredential } from "../src/verification/index.js";
import { definePolicy, requireCredential, requireVouches, evaluate } from "../src/policy/index.js";

const issuer = generateIdentity();
const agentA = generateIdentity();
const voucher = generateIdentity();

const TRUSTED_ISSUERS = [issuer.did];
const TRUSTED_VOUCHERS = [voucher.did];

const purchasePolicy = definePolicy("purchase", [
  requireCredential(
    "AuthorityScopeCredential",
    "AuthorityScopeCredential: limit >= $300, from a trusted issuer",
    (subj, iss) => TRUSTED_ISSUERS.includes(iss) && subj.domain === "purchasing" && (subj.limit as number) >= 300,
  ),
  requireCredential(
    "ActionHistoryCredential",
    "ActionHistoryCredential: successRate >= 0.9",
    (subj) => (subj.successRate as number) >= 0.9,
  ),
  requireVouches(1, TRUSTED_VOUCHERS),
]);

async function verifiedFrom(jwts: string[]): Promise<VerifiedCredential[]> {
  const results = await Promise.all(jwts.map(verifyCredential));
  return results.filter((r): r is { valid: true; credential: VerifiedCredential } => r.valid).map((r) => r.credential);
}

// Case A: agent A has everything required -> accept
const scopeVc = await issueCredential(issuer, agentA.did, "AuthorityScopeCredential", {
  domain: "purchasing",
  limit: 500,
  unit: "USD",
});
const historyVc = await issueCredential(issuer, agentA.did, "ActionHistoryCredential", {
  domain: "purchasing",
  tasksCompleted: 42,
  successRate: 0.95,
});
const vouchVc = await issueCredential(voucher, agentA.did, "VouchCredential", {
  statement: "Worked with this agent for 6 months, reliable.",
});

const verifiedFull = await verifiedFrom([scopeVc, historyVc, vouchVc]);
console.log(
  "Case A (full credentials):",
  JSON.stringify(evaluate(purchasePolicy, verifiedFull, { holderDid: agentA.did }), null, 2),
);

// Case B: missing vouch -> refuse, trace shows exactly which rule failed
const verifiedNoVouch = await verifiedFrom([scopeVc, historyVc]);
console.log(
  "Case B (no vouch):",
  JSON.stringify(evaluate(purchasePolicy, verifiedNoVouch, { holderDid: agentA.did }), null, 2),
);

// Case C: scope limit too low -> refuse
const lowScopeVc = await issueCredential(issuer, agentA.did, "AuthorityScopeCredential", {
  domain: "purchasing",
  limit: 100,
  unit: "USD",
});
const verifiedLowScope = await verifiedFrom([lowScopeVc, historyVc, vouchVc]);
console.log(
  "Case C (scope too low):",
  JSON.stringify(evaluate(purchasePolicy, verifiedLowScope, { holderDid: agentA.did }), null, 2),
);

// Case D: holder-binding — Mallory bundles Agent A's genuine credentials as her own
const mallory = generateIdentity();
const verifiedStolen = await verifiedFrom([scopeVc, historyVc, vouchVc]);
console.log(
  "Case D (stolen credentials, wrong holder):",
  JSON.stringify(evaluate(purchasePolicy, verifiedStolen, { holderDid: mallory.did }), null, 2),
);
