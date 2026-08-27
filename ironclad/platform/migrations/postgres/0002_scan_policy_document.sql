-- Record the policy document that was actually applied to a scan.
--
-- A scan may be gated by an inline policy supplied in the request body,
-- which has no row in `policies`. Without persisting the document, the
-- decision cannot be recomputed later and `GET /scan/{id}/result` would
-- silently report "no policy" for a scan that was in fact gated.
ALTER TABLE scans ADD COLUMN policy_document TEXT NOT NULL DEFAULT '';
