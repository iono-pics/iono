alter table domain_settings
    add column files_path_prefix TEXT CHECK (files_path_prefix IS NULL OR (files_path_prefix ~ '^[a-zA-Z0-9_-]+$' AND files_path_prefix <> 'raw')),
    add column pastes_path_prefix TEXT CHECK (pastes_path_prefix IS NULL OR pastes_path_prefix ~ '^[a-zA-Z0-9_-]+$'),
    add column short_links_path_prefix TEXT CHECK (short_links_path_prefix IS NULL OR short_links_path_prefix ~ '^[a-zA-Z0-9_-]+$');
