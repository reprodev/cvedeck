"""Remediation service for manually maintained remediation records.

The :class:`RemediationService` is the administrator-facing surface for creating
and updating remediation records (a status plus a free-text note) for a CVE on a
Target_Machine. It delegates persistence to the :class:`~app.data.repository.Repository`
so records are written to the Local_Database (Req 4.1, 4.3) with a status and
free-text note (Req 4.2).

Remediation is only ever performed through the explicit ``add`` / ``update``
method calls below. There is deliberately no scheduler, timer, or background
trigger in this module: remediation actions happen only when an administrator
invokes them (Req 4.5), and no command is ever executed on a target
(Req 14.6). The service owns no transaction thread of its own — it
simply calls the repository on the caller's behalf.
"""

from __future__ import annotations

from ..data.repository import RemediationInput, Repository
from ..data.schema import RemediationRecord
from ..enums import RemediationStatus


class RemediationRecordNotFoundError(LookupError):
    """Raised when an update targets a remediation record that does not exist."""

    def __init__(self, record_id: str) -> None:
        self.record_id = record_id
        super().__init__(f"No remediation record with id {record_id!r}")


class RemediationService:
    """Create and update manually maintained remediation records (Req 4).

    Wraps a :class:`~app.data.repository.Repository` and exposes the two
    administrator-initiated operations described in the design: :meth:`add` and
    :meth:`update`. Both persist the record to the Local_Database via the
    repository. No automated/scheduled trigger exists — the service acts only
    when one of these methods is called (Req 4.5).
    """

    def __init__(self, repository: Repository) -> None:
        self._repository = repository

    def add(
        self,
        machine_id: str,
        cve_id: str,
        status: RemediationStatus,
        note: str,
    ) -> RemediationRecord:
        """Add a new remediation record for a CVE on a machine (Req 4.1, 4.2).

        Persists a record capturing the given remediation ``status`` and
        free-text ``note`` to the Local_Database.

        Args:
            machine_id: The Target_Machine the CVE was found on.
            cve_id: The CVE the remediation record tracks.
            status: The remediation status to record.
            note: The administrator's free-text note.

        Returns:
            The persisted :class:`RemediationRecord` (with generated id).
        """
        return self._repository.add_remediation(
            machine_id,
            cve_id,
            RemediationInput(status=status, note=note),
        )

    def update(
        self,
        record_id: str,
        status: RemediationStatus,
        note: str,
    ) -> RemediationRecord:
        """Update an existing remediation record's status/note (Req 4.3, 4.2).

        Persists the updated ``status`` and free-text ``note`` for the record
        identified by ``record_id`` to the Local_Database.

        Args:
            record_id: The id of the remediation record to update.
            status: The new remediation status.
            note: The new free-text note.

        Returns:
            The updated :class:`RemediationRecord`.

        Raises:
            RemediationRecordNotFoundError: If no record with ``record_id`` exists.
        """
        updated = self._repository.update_remediation(
            record_id,
            RemediationInput(status=status, note=note),
        )
        if updated is None:
            raise RemediationRecordNotFoundError(record_id)
        return updated
