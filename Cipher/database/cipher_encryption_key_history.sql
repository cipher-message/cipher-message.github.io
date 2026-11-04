-- Preserve earlier wrapped E2EE keys before the active key is replaced.
-- Historical private keys remain encrypted with the user's original passphrase.
create table if not exists private.profile_key_history (
  id uuid primary key default pg_catalog.gen_random_uuid(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  public_key jsonb not null,
  wrapped_private_key text not null,
  wrap_iv text not null,
  wrap_salt text not null,
  created_at timestamptz not null default pg_catalog.now(),
  constraint profile_key_history_size check (
    pg_column_size(public_key) <= 4096
    and length(wrapped_private_key) <= 4096
    and length(wrap_iv) <= 128
    and length(wrap_salt) <= 128
  ),
  constraint profile_key_history_unique_key unique (user_id, public_key)
);

alter table private.profile_key_history enable row level security;
revoke all on table private.profile_key_history from public, anon, authenticated, service_role;

-- Key updates now pass through the authenticated RPC so rotation always archives
-- the prior public/wrapped-private-key pair atomically before replacing it.
revoke insert, update on public.profile_secrets from authenticated;
grant select on public.profile_secrets to authenticated;

create or replace function public.set_my_encryption_key(
  p_public_key jsonb,
  p_wrapped_private_key text,
  p_wrap_iv text,
  p_wrap_salt text
) returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_uid uuid := (select auth.uid());
  v_old_public_key jsonb;
  v_old_wrapped text;
  v_old_iv text;
  v_old_salt text;
begin
  if v_uid is null then
    raise exception 'not authenticated' using errcode = '42501';
  end if;
  if jsonb_typeof(p_public_key) <> 'object' or pg_column_size(p_public_key) > 4096
     or p_wrapped_private_key is null or length(p_wrapped_private_key) > 4096
     or p_wrap_iv is null or length(p_wrap_iv) > 128
     or p_wrap_salt is null or length(p_wrap_salt) > 128 then
    raise exception 'invalid encryption key metadata' using errcode = '22023';
  end if;

  select p.public_key into v_old_public_key
  from public.profiles as p
  where p.id = v_uid
  for update;
  if not found then
    raise exception 'profile unavailable' using errcode = '42501';
  end if;

  select s.wrapped_private_key, s.wrap_iv, s.wrap_salt
  into v_old_wrapped, v_old_iv, v_old_salt
  from public.profile_secrets as s
  where s.user_id = v_uid
  for update;

  if v_old_public_key is not null and v_old_public_key is distinct from p_public_key
     and v_old_wrapped is not null and v_old_iv is not null and v_old_salt is not null then
    insert into private.profile_key_history
      (user_id, public_key, wrapped_private_key, wrap_iv, wrap_salt)
    values
      (v_uid, v_old_public_key, v_old_wrapped, v_old_iv, v_old_salt)
    on conflict (user_id, public_key) do nothing;
  end if;

  update public.profiles set public_key = p_public_key where id = v_uid;
  insert into public.profile_secrets(user_id, wrapped_private_key, wrap_iv, wrap_salt, updated_at)
  values (v_uid, p_wrapped_private_key, p_wrap_iv, p_wrap_salt, pg_catalog.clock_timestamp())
  on conflict (user_id) do update set
    wrapped_private_key = excluded.wrapped_private_key,
    wrap_iv = excluded.wrap_iv,
    wrap_salt = excluded.wrap_salt,
    updated_at = excluded.updated_at;
end;
$$;
revoke all on function public.set_my_encryption_key(jsonb, text, text, text) from public, anon;
grant execute on function public.set_my_encryption_key(jsonb, text, text, text) to authenticated;

create or replace function public.get_my_encryption_key_history()
returns table (
  id uuid,
  public_key jsonb,
  wrapped_private_key text,
  wrap_iv text,
  wrap_salt text,
  created_at timestamptz
)
language sql
security definer
set search_path = ''
as $$
  select h.id, h.public_key, h.wrapped_private_key, h.wrap_iv, h.wrap_salt, h.created_at
  from private.profile_key_history as h
  where h.user_id = (select auth.uid())
  order by h.created_at desc
$$;
revoke all on function public.get_my_encryption_key_history() from public, anon;
grant execute on function public.get_my_encryption_key_history() to authenticated;
