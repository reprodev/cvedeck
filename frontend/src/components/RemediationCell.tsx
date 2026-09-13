// Per-finding remediation editor: a status select, a free-text note, and a save
// button, rendered in the last column of the findings table.
//
// Local state rather than lifted: the row holds a draft until Save is pressed,
// so typing a note does not fire a request per keystroke, and abandoning a row
// leaves no trace. The parent owns persistence and re-seeds this component from
// props when the finding reloads.

import { useState } from "react";

import { REMEDIATION_STATUSES } from "../types";
import type { CveFinding, RemediationStatus } from "../types";
import { remediationStatusLabel } from "../lib/labels";

export interface RemediationCellProps {
  finding: CveFinding;
  onSave: (
    finding: CveFinding,
    status: RemediationStatus,
    note: string,
  ) => void;
}


export function RemediationCell({ finding, onSave }: RemediationCellProps) {
  const [status, setStatus] = useState<RemediationStatus>(
    (finding.remediationStatus as RemediationStatus | null) ?? "open",
  );
  const [note, setNote] = useState(finding.remediationNote ?? "");

  const cveId = finding.cveId;
  const statusId = `remediation-status-${cveId}`;
  const noteId = `remediation-note-${cveId}`;

  return (
    <div className="remediation-cell">
      <label className="visually-hidden" htmlFor={statusId}>
        Remediation status for {cveId}
      </label>
      <select
        id={statusId}
        value={status}
        onChange={(e) => setStatus(e.target.value as RemediationStatus)}
      >
        {REMEDIATION_STATUSES.map((value) => (
          <option key={value} value={value}>
            {remediationStatusLabel(value)}
          </option>
        ))}
      </select>

      <label className="visually-hidden" htmlFor={noteId}>
        Remediation note for {cveId}
      </label>
      <input
        id={noteId}
        type="text"
        value={note}
        placeholder="Note"
        onChange={(e) => setNote(e.target.value)}
      />

      <button
        type="button"
        onClick={() => onSave(finding, status, note)}
        aria-label={`Save remediation for ${cveId}`}
      >
        Save
      </button>
    </div>
  );
}
