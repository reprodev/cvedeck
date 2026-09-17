// One vocabulary for blast radius, shared by the badge, the card and the
// dialog (Req 10.10).
//
// They disagreed. The badge read the backend's three tiers -- 10 or more
// dependents is high, 3 or more is medium, otherwise low -- while the card and
// the dialog asked only "does anything depend on this?" and shouted "HIGH
// SYSTEM IMPACT" / "DO NOT REMOVE THIS PACKAGE" whenever the answer was yes.
// A package with three dependents therefore carried a "Moderate (3 apps)"
// badge beside a card telling the reader never to remove it, which is the kind
// of disagreement that teaches people to believe neither.

import type { BlastRadius } from "../types";

export interface ImpactTone {
  /** Badge class, e.g. `badge-blast-high`. */
  badgeClass: string;
  /** Card class, e.g. `warning-card-high`. */
  cardClass: string;
  /** Title-case tier name for a badge: "High", "Moderate", "Low". */
  label: string;
  /** Sentence-case heading for a card, without the dependent count. */
  heading: string;
  /** What the reader should do about it. */
  advice: string;
  /** CSS custom property carrying the tier's colour. */
  colorVar: string;
}

const TONES: Record<"high" | "medium" | "low", ImpactTone> = {
  high: {
    badgeClass: "badge-blast-high",
    cardClass: "warning-card-high",
    label: "High",
    heading: "High system impact",
    advice: "Do not purge. Apply a selective package upgrade when one is published.",
    colorVar: "var(--impact-high)",
  },
  medium: {
    badgeClass: "badge-blast-medium",
    cardClass: "warning-card-medium",
    label: "Moderate",
    heading: "Moderate system impact",
    advice:
      "Check each dependent application before removing this package; upgrading it is the safer route.",
    colorVar: "var(--warn-text)",
  },
  low: {
    badgeClass: "badge-blast-low",
    cardClass: "warning-card-low",
    label: "Low",
    heading: "Low system impact",
    advice:
      "Few packages depend on this one, but confirm the dependents below are not in use before removing it.",
    colorVar: "var(--ok-text)",
  },
};

/**
 * The treatment for a measured blast radius, or ``null`` when none was
 * measured -- which is its own state, never the bottom of the scale.
 */
export function impactTone(blastRadius: BlastRadius | null | undefined): ImpactTone | null {
  if (blastRadius === "high" || blastRadius === "medium" || blastRadius === "low") {
    return TONES[blastRadius];
  }
  return null;
}

/** A badge's text: the tier and how many packages it was measured from. */
export function impactBadgeLabel(tone: ImpactTone, dependents: number): string {
  return `${tone.label} (${dependents} ${dependents === 1 ? "app" : "apps"})`;
}
