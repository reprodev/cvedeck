"""Service layer: orchestration on top of the persistence layer.

Hosts application services that coordinate persistence and cross-store
behavior, such as :class:`app.services.sync.SyncService`, which propagates
locally written rows to the Online_Database.
"""
