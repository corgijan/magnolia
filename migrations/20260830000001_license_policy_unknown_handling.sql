-- Replaces tenant_license_policies.flag_unknown (bool) with a 3-way
-- unknown_license_handling ('ignore' | 'warn' | 'flag'): a component with no
-- usable license info can now be reported as a non-blocking "warn" instead
-- of the old binary ignore/flag-as-full-violation choice. See
-- magnolia_core::license::{UnknownLicenseHandling, license_policy_status}.
ALTER TABLE tenant_license_policies
    ADD COLUMN unknown_license_handling VARCHAR(10) NOT NULL DEFAULT 'ignore';

UPDATE tenant_license_policies
SET unknown_license_handling = CASE WHEN flag_unknown THEN 'flag' ELSE 'ignore' END;

ALTER TABLE tenant_license_policies
    ADD CONSTRAINT tenant_license_policies_unknown_handling_check
        CHECK (unknown_license_handling IN ('ignore', 'warn', 'flag'));

ALTER TABLE tenant_license_policies DROP COLUMN flag_unknown;
