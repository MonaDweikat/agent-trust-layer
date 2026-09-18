/**
 * Agent layer: wraps an identity, a credential wallet, and the two behaviors
 * a demo needs — presenting credentials to request a task, and evaluating an
 * incoming request against a policy.
 *
 * An agent only ever proves things about itself via signed credentials it
 * holds — it never asserts trust about itself in plaintext. That's the
 * structural difference between this and a "reputation score" field: there
 * is no field on Agent for "how trusted am I", only a wallet of credentials
 * someone else issued.
 */

import { generateIdentity, type AgentIdentity } from "../identity/index.js";
import { createPresentation } from "../credentials/index.js";
import { verifyPresentation, type VerifiedCredential } from "../verification/index.js";
import { evaluate, type Policy, type PolicyDecision } from "../policy/index.js";

export interface TaskParams {
  /** Task-specific parameters a policy rule may check against, e.g. a requested spend amount. */
  [key: string]: unknown;
}

export interface TaskRequest {
  taskType: string;
  description: string;
  params: TaskParams;
  presentation: string; // VP-JWT
}

export interface TaskEvaluation extends PolicyDecision {
  requesterDid: string | undefined;
  holderValid: boolean;
  holderReason?: string;
}

export class Agent {
  readonly identity: AgentIdentity;
  readonly name: string;
  private wallet: string[] = []; // VC-JWTs this agent holds

  constructor(name: string, identity: AgentIdentity = generateIdentity()) {
    this.name = name;
    this.identity = identity;
  }

  get did(): string {
    return this.identity.did;
  }

  hold(credentialJwt: string): void {
    this.wallet.push(credentialJwt);
  }

  /** Bundle this agent's wallet into a signed VP and build a task request. */
  async requestTask(taskType: string, description: string, params: TaskParams = {}): Promise<TaskRequest> {
    const presentation = await createPresentation(this.identity, this.wallet);
    return { taskType, description, params, presentation };
  }

  /**
   * Verify the incoming request's presentation, then run the given policy
   * against the verified credentials only. Logs nothing itself — callers
   * (the demo scripts) render the trace so the decision stays visible.
   */
  async evaluateRequest(request: TaskRequest, policy: Policy): Promise<TaskEvaluation> {
    const verification = await verifyPresentation(request.presentation);

    if (!verification.holderValid) {
      return {
        requesterDid: verification.holderDid,
        holderValid: false,
        holderReason: verification.holderReason,
        decision: "refuse",
        trace: [{ description: "presentation holder signature must verify", passed: false }],
      };
    }

    const verifiedCredentials: VerifiedCredential[] = verification.credentials
      .filter((r): r is { valid: true; credential: VerifiedCredential } => r.valid)
      .map((r) => r.credential);

    const { decision, trace } = evaluate(policy, verifiedCredentials, {
      holderDid: verification.holderDid!,
      task: request.params,
    });

    return {
      requesterDid: verification.holderDid,
      holderValid: true,
      decision,
      trace,
    };
  }
}
