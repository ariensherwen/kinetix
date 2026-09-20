-- Immutable plugin package provenance and rollback inputs.
--
-- Accepted .kxp bytes are stored under KINETIX_DATA_DIR/plugins/packages using
-- content-addressed filenames. This table indexes those artifacts independently
-- from the currently active plugin row, so uninstalling a plugin does not erase
-- package provenance or cached rollback inputs.

CREATE TABLE IF NOT EXISTS plugin_packages (
    plugin_id       TEXT NOT NULL,
    version         TEXT NOT NULL,
    package_sha256  TEXT NOT NULL,
    package_path    TEXT NOT NULL,
    signature       TEXT NOT NULL,
    source          TEXT NOT NULL DEFAULT 'local',
    installed_at    TEXT NOT NULL,
    PRIMARY KEY (plugin_id, package_sha256)
);

CREATE INDEX IF NOT EXISTS idx_plugin_packages_plugin_installed
    ON plugin_packages(plugin_id, installed_at DESC);
