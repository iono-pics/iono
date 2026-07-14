alter table users add column deleted_at TIMESTAMPTZ;

create index users_deleted_at_idx on users (deleted_at) where deleted_at is not null;
