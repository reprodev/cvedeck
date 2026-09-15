// Human-readable labels for the enum-ish strings the backend sends.
//
// These lived in three places before: `statusLabel` was defined inside
// ScanFormView, MachineListView rendered the raw enum (`connection_failure`)
// because it could not reach it, and `severityLabel` was duplicated verbatim in
// two views. One home means one vocabulary.

import type { Severity } from "../types";

/** Title-case a severity for display ("critical" -> "Critical"). */
export function severityLabel(severity: Severity | string): string {
  return severity.charAt(0).toUpperCase() + severity.slice(1);
}

/** Human-readable label for a machine's last scan status. */
export function statusLabel(status: string): string {
  switch (status) {
    case "success":
      return "Success";
    case "never_scanned":
      return "Never scanned";
    case "connection_failure":
      return "Could not connect";
    case "auth_failure":
      return "Authentication failed";
    case "host_key_mismatch":
      return "Host key changed";
    case "host_key_unknown":
      return "Host key not pinned";
    default:
      return status;
  }
}

/**
 * Which visual treatment a scan status gets.
 *
 * `never_scanned` is deliberately neutral rather than a failure: a host
 * enrolled from discovery has had nothing attempted against it, and showing it
 * in red taught users to ignore red.
 *
 * A refused host key is `warn`: amber, like every other caveat. It is not
 * exploitation, the only thing red is for, and it is not an ordinary failure
 * to retry either. Someone has to look at it (Req 17.3).
 */
export function statusTone(
  status: string,
): "success" | "neutral" | "warn" | "failure" {
  if (status === "success") return "success";
  if (status === "never_scanned") return "neutral";
  if (isHostKeyStatus(status)) return "warn";
  return "failure";
}

/** Whether a scan status is a refused SSH host key (Req 17.3, 17.5). */
export function isHostKeyStatus(status: string): boolean {
  const lower = status.toLowerCase();
  return lower === "host_key_mismatch" || lower === "host_key_unknown";
}

/** Human-readable label for a remediation status. */
export function remediationStatusLabel(status: string): string {
  // Title Case, matching what the drill-down has always rendered. This module
  // previously carried a sentence-case switch ("In progress") that nothing
  // imported, while the drill-down kept its own Title Case copy -- two
  // implementations of one function, disagreeing, waiting for someone to import
  // the wrong one and change the UI by accident.
  //
  // Generic rather than a switch over the four known statuses: a status added
  // to the enum renders readably here instead of leaking its raw snake_case.
  return status
    .split("_")
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(" ");
}

/** Age in days of an ISO-8601 timestamp, or null when absent/unparseable. */
export function ageInDays(iso: string | null, now: Date = new Date()): number | null {
  if (!iso) return null;
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return null;
  return (now.getTime() - then) / 86_400_000;
}

/**
 * Compact relative time ("3h ago"). Returns "Never" for a null timestamp, which
 * is the honest answer for a host that has never been scanned -- previously the
 * UI could not distinguish that from a host scanned moments ago with 0 findings.
 */
export function relativeTime(iso: string | null, now: Date = new Date()): string {
  const days = ageInDays(iso, now);
  if (days === null) return "Never";
  if (days < 0) return "Just now";
  const minutes = days * 1440;
  if (minutes < 1) return "Just now";
  if (minutes < 60) return `${Math.floor(minutes)}m ago`;
  if (days < 1) return `${Math.floor(minutes / 60)}h ago`;
  if (days < 30) return `${Math.floor(days)}d ago`;
  if (days < 365) return `${Math.floor(days / 30)}mo ago`;
  return `${Math.floor(days / 365)}y ago`;
}

/** Scans older than this are called out as stale in the fleet view (Req 10.5). */
export const STALE_AFTER_DAYS = 7;

/**
 * Whether a scan is old enough that its findings should not be trusted as
 * current (Req 10.5).
 */
export function isStale(iso: string | null, now: Date = new Date()): boolean {
  const days = ageInDays(iso, now);
  return days !== null && days > STALE_AFTER_DAYS;
}
