export type ScanVerdict = "Clean" | "Inconclusive" | "Suspicious" | "Flagged";

export interface ScanFinding {
  module: string;
  verdict: ScanVerdict;
  description: string;
  details: string | null;
  timestamp: string;
}

export type AccountProvider = "discord" | "roblox";

export interface LinkedAccount {
  provider: string;
  id: string;
  username: string;
  verified: boolean;
}

export interface AccountIdentity {
  provider: AccountProvider;
  id: string;
  username: string;
  display_name: string | null;
  profile_url: string | null;
  avatar_url: string | null;
  verified_at: string;
  source: string;
  linked_accounts: LinkedAccount[];
}

export interface ScanReport {
  scan_id: string;
  timestamp: string;
  machine_id: string;
  os_info: string;
  overall_verdict: ScanVerdict;
  findings: ScanFinding[];
  hmac_signature: string;
}
