drop index api_keys_user_id_idx;
alter table api_keys add constraint api_keys_user_id_key unique (user_id);
