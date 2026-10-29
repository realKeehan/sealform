// Identity and assurance checks. Each one adds evidence about who signed. Only the email receipt is
// on by default; the rest are declared here so documents and jurisdiction profiles can name them, and
// a document that requires an unconfigured check refuses to publish.

import type { AssuranceCheck } from '../core/index.ts';

export interface CheckContext {
  recordId: string;
  fields: Record<string, unknown>;
}

export interface Check {
  kind: string;
  description: string;
  /** Assurance this check adds when it passes, for the record's assurance.level. */
  adds: string;
  enabled: boolean;
  /** Runs before sealing. Returns the evidence entry for the record, or throws to block signing. */
  run(context: CheckContext): Promise<AssuranceCheck>;
}

export class CheckNotConfiguredError extends Error {
  constructor(kind: string) {
    super(`Check "${kind}" is not configured on this server`);
  }
}

function disabled(kind: string, description: string, adds: string): Check {
  return {
    kind,
    description,
    adds,
    enabled: false,
    run: () => Promise.reject(new CheckNotConfiguredError(kind)),
  };
}

/** The receipt itself is sent after sealing; this records that it was queued. */
export const emailReceiptCheck: Check = {
  kind: 'email-receipt',
  description: 'Sends the signer a copy of the signed record at the email address they gave.',
  adds: 'delivery-to-stated-address',
  enabled: true,
  run: () => Promise.resolve({ kind: 'email-receipt', status: 'queued' }),
};

export function defaultChecks(): Map<string, Check> {
  const checks: Check[] = [
    emailReceiptCheck,
    disabled('email-otp', 'One-time code to the signer\'s email before signing: proves control of the mailbox.', 'email-verified'),
    disabled('sms-otp', 'One-time code by SMS: proves control of a phone number. Needs an SMS provider.', 'phone-verified'),
    disabled('passkey', 'WebAuthn passkey: binds the signature to a device the signer controls.', 'device-bound'),
    disabled('id-document', 'Government ID with a liveness check through an identity provider.', 'identity-verified'),
    disabled('qes', 'Qualified electronic signature through an eIDAS trust service provider.', 'qes'),
    disabled('tsa', 'RFC 3161 timestamp on the record hash from an independent timestamp authority.', 'independent-time'),
    disabled('pades', 'Certificate signature embedded in the PDF copy, shown as signed by PDF readers.', 'pdf-certified'),
  ];
  return new Map(checks.map((check) => [check.kind, check]));
}
