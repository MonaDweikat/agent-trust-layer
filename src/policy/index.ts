/**
 * Policy layer: turns a set of verified claims into an accept/refuse
 * decision. Deliberately NOT a single "trust score" — a policy is a
 * declarative rule set scoped to a task type, and evaluation produces a
 * trace of which rule passed or failed and why, so the decision is
 * explainable rather than a magic number.
 *
 * A policy only ever sees VerifiedCredential objects that already passed
 * signature/expiry/revocation checks (src/verification) — nothing a
 * counterparty merely claims in plaintext is visible here.
 *
 * Rules also receive the presentation's holder DID, because "this credential
 * is genuine" is not the same question as "this credential is about the
 * entity presenting it." A rule that skips that second check would accept
 * anyone bundling a copy of someone else's valid credential — see
 * requireCredential's `bindSubjectToHolder` (on by default).
 */

import type { VerifiedCredential } from "../verification/index.js";
import type { CredentialType } from "../credentials/types.js";

export interface EvaluationContext {
  /** DID of the agent presenting the credentials — see requireCredential's bindSubjectToHolder. */
  holderDid: string;
  /** Task-specific parameters a rule may need, e.g. { amount: 300 } for a purchase task. */
  task?: Record<string, unknown>;
}

export interface Rule {
  description: string;
  /** Returns true if this rule is satisfied given the verified credentials and the evaluation context. */
  check: (verified: VerifiedCredential[], context: EvaluationContext) => boolean;
}

export interface Policy {
  taskType: string;
  rules: Rule[];
}

export interface RuleResult {
  description: string;
  passed: boolean;
}

export interface PolicyDecision {
  decision: "accept" | "refuse";
  trace: RuleResult[];
}

export interface RequireCredentialOptions {
  /**
   * Require credential.subject === the presenting agent's DID (default true).
   * Set to false only when a rule intentionally inspects a credential about
   * someone else as supporting evidence (e.g. a delegator's own authority
   * credential, bundled to prove a delegation chain — see
   * demo/policies.ts's delegated-authority rule).
   */
  bindSubjectToHolder?: boolean;
}

/** Helper: build a rule requiring at least one verified credential of a type whose claims satisfy a predicate. */
export function requireCredential(
  type: CredentialType,
  description: string,
  predicate: (credentialSubject: Record<string, unknown>, issuer: string) => boolean,
  opts: RequireCredentialOptions = {},
): Rule {
  const bind = opts.bindSubjectToHolder ?? true;
  return {
    description,
    check: (verified, context) =>
      verified.some(
        (c) =>
          c.type === type &&
          (!bind || c.subject === context.holderDid) &&
          predicate(c.credentialSubject, c.issuer),
      ),
  };
}

/** Helper: build a rule requiring at least `min` VouchCredentials, about the presenter, from trusted issuers. */
export function requireVouches(min: number, trustedIssuers: string[]): Rule {
  return {
    description: `at least ${min} vouch(es) about the presenter from a trusted voucher`,
    check: (verified, context) =>
      verified.filter(
        (c) => c.type === "VouchCredential" && c.subject === context.holderDid && trustedIssuers.includes(c.issuer),
      ).length >= min,
  };
}

export function definePolicy(taskType: string, rules: Rule[]): Policy {
  return { taskType, rules };
}

/** Evaluate a policy against a set of already-verified credentials, producing a full trace. */
export function evaluate(policy: Policy, verified: VerifiedCredential[], context: EvaluationContext): PolicyDecision {
  const trace: RuleResult[] = policy.rules.map((rule) => ({
    description: rule.description,
    passed: rule.check(verified, context),
  }));

  const decision: PolicyDecision["decision"] = trace.every((r) => r.passed) ? "accept" : "refuse";
  return { decision, trace };
}
