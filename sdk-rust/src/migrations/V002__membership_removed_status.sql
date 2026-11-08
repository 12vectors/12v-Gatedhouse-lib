-- Gatedhouse schema, version 2.
--
-- Adds the 'removed' membership status. Memberships are no longer deleted:
-- an identity leaving an org moves to 'removed', which revokes its grants in
-- that org while keeping the membership row as history. See docs/MODEL.md.
--
-- ALTER TYPE ... ADD VALUE may run inside the migration's transaction
-- (PostgreSQL 12+); the new value is only used by later transactions.

ALTER TYPE gatedhouse.membership_status ADD VALUE IF NOT EXISTS 'removed';
