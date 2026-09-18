export type CredentialType =
  | "ActionHistoryCredential"
  | "AuthorityScopeCredential"
  | "VouchCredential"
  | "DelegatedAuthorityCredential";

export interface ActionHistoryClaims {
  tasksCompleted: number;
  successRate: number; // 0..1
  domain: string;
}

export interface AuthorityScopeClaims {
  domain: string; // e.g. "purchasing"
  limit: number; // max scope, e.g. max spend in USD
  unit: string; // e.g. "USD"
}

export interface VouchClaims {
  statement: string; // human-readable reason for the vouch
}

export interface DelegatedAuthorityClaims {
  domain: string;
  limit: number;
  unit: string;
  /** jti of the delegator's own AuthorityScopeCredential this delegation is carved out of. */
  parentCredentialJti: string;
}

export type CredentialClaims =
  | ActionHistoryClaims
  | AuthorityScopeClaims
  | VouchClaims
  | DelegatedAuthorityClaims;

export interface VcPayload {
  vc: {
    "@context": string[];
    type: ["VerifiableCredential", CredentialType];
    credentialSubject: { id: string } & Record<string, unknown>;
  };
}

export interface VpPayload {
  vp: {
    "@context": string[];
    type: ["VerifiablePresentation"];
    verifiableCredential: string[];
  };
}
