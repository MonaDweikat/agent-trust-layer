/**
 * Demo-specific policy rules that go beyond the generic `requireCredential`
 * helper because they need to reason across more than one credential at
 * once, or against the specific task being requested rather than a fixed
 * threshold. Kept out of src/policy (which stays a general rule engine) so
 * the core engine doesn't accumulate one-off logic for a single demo.
 */

import type { EvaluationContext, Rule } from "../src/policy/index.js";
import type { VerifiedCredential } from "../src/verification/index.js";

/**
 * Walks a chain of custody back to a trusted root, at arbitrary depth.
 *
 * `credentialJti` must name a credential, held by `holderDid`, in `domain`,
 * covering at least `minAmount`:
 *   - if it's an AuthorityScopeCredential, the chain terminates here — valid
 *     only if issued by a trusted issuer.
 *   - if it's a DelegatedAuthorityCredential, the delegator (its issuer)
 *     must themselves hold the credential it claims as `parentCredentialJti`
 *     — checked recursively, so a delegator can never hand out more than
 *     they can prove they were handed. `visited` guards against a cycle of
 *     credentials citing each other as their own parent.
 */
function isValidAuthorityCredential(
  verified: VerifiedCredential[],
  credentialJti: string,
  holderDid: string,
  domain: string,
  minAmount: number,
  trustedIssuers: string[],
  visited: Set<string>,
): boolean {
  if (visited.has(credentialJti)) return false;
  visited.add(credentialJti);

  const credential = verified.find(
    (c) => c.jti === credentialJti && c.subject === holderDid && c.credentialSubject.domain === domain,
  );
  if (!credential) return false;

  const limit = credential.credentialSubject.limit as number;
  if (limit < minAmount) return false;

  if (credential.type === "AuthorityScopeCredential") {
    return trustedIssuers.includes(credential.issuer);
  }

  if (credential.type === "DelegatedAuthorityCredential") {
    const delegatorDid = credential.issuer;
    const parentJti = credential.credentialSubject.parentCredentialJti as string;
    // The delegator must be able to prove THEY held at least `limit` —
    // i.e. at least as much as they just gave away — via their own parent link.
    return isValidAuthorityCredential(verified, parentJti, delegatorDid, domain, limit, trustedIssuers, visited);
  }

  return false;
}

/**
 * Authorization for a domain, checked against the task's requested amount
 * (context.task.amount) rather than a limit fixed at policy-definition
 * time — a $150 request and a $600 request against the same policy need
 * different amounts of authority, not the same threshold.
 *
 * Satisfied by any credential the presenter holds — directly-granted or
 * delegated at any chain depth — whose chain of custody traces back to a
 * trusted issuer without ever exceeding what an earlier link actually held.
 */
export function requireAuthorityScope(domain: string, trustedIssuers: string[]): Rule {
  return {
    description: `authorized for "${domain}" up to the requested amount (directly or via a delegation chain of any depth, rooted in a trusted issuer)`,
    check: (verified: VerifiedCredential[], context: EvaluationContext) => {
      const amount = context.task?.amount as number | undefined;
      if (amount === undefined) return false; // can't authorize an unspecified amount

      return verified.some(
        (c) =>
          (c.type === "AuthorityScopeCredential" || c.type === "DelegatedAuthorityCredential") &&
          c.subject === context.holderDid &&
          c.credentialSubject.domain === domain &&
          (c.credentialSubject.limit as number) >= amount &&
          isValidAuthorityCredential(verified, c.jti, context.holderDid, domain, amount, trustedIssuers, new Set()),
      );
    },
  };
}
