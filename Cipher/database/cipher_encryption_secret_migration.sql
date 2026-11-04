-- Add a private-by-row store for wrapped private keys before deploying the
-- frontend that reads it. Existing profile permissions remain untouched here.
begin;

create table if not exists public.profile_secrets (
  user_id uuid primary key references public.profiles(id) on delete cascade,
  wrapped_private_key text,
  wrap_iv text,
  wrap_salt text,
  updated_at timestamptz not null default now()
);
alter table public.profile_secrets enable row level security;
revoke all on public.profile_secrets from public, anon;
grant select, insert, update on public.profile_secrets to authenticated;

drop policy if exists "profile_secrets_select_self" on public.profile_secrets;
create policy "profile_secrets_select_self" on public.profile_secrets
for select to authenticated using (user_id = (select auth.uid()));
drop policy if exists "profile_secrets_insert_self" on public.profile_secrets;
create policy "profile_secrets_insert_self" on public.profile_secrets
for insert to authenticated with check (user_id = (select auth.uid()));
drop policy if exists "profile_secrets_update_self" on public.profile_secrets;
create policy "profile_secrets_update_self" on public.profile_secrets
for update to authenticated using (user_id = (select auth.uid()))
with check (user_id = (select auth.uid()));

insert into public.profile_secrets(user_id, wrapped_private_key, wrap_iv, wrap_salt)
select id, wrapped_private_key, wrap_iv, wrap_salt
from public.profiles
where wrapped_private_key is not null or wrap_iv is not null or wrap_salt is not null
on conflict (user_id) do nothing;

create or replace function public.set_my_encryption_key(
  p_public_key jsonb,
  p_wrapped_private_key text,
  p_wrap_iv text,
  p_wrap_salt text
) returns void
language plpgsql
security invoker
set search_path = ''
as $$
declare v_uid uuid := (select auth.uid());
begin
  if v_uid is null then raise exception 'not authenticated' using errcode = '42501'; end if;
  if jsonb_typeof(p_public_key) <> 'object' or pg_column_size(p_public_key) > 4096
     or p_wrapped_private_key is null or length(p_wrapped_private_key) > 4096
     or p_wrap_iv is null or length(p_wrap_iv) > 128
     or p_wrap_salt is null or length(p_wrap_salt) > 128 then
    raise exception 'invalid encryption key metadata' using errcode = '22023';
  end if;
  update public.profiles set public_key = p_public_key where id = v_uid;
  if not found then raise exception 'profile unavailable' using errcode = '42501'; end if;
  insert into public.profile_secrets(user_id, wrapped_private_key, wrap_iv, wrap_salt, updated_at)
  values (v_uid, p_wrapped_private_key, p_wrap_iv, p_wrap_salt, clock_timestamp())
  on conflict (user_id) do update set
    wrapped_private_key = excluded.wrapped_private_key,
    wrap_iv = excluded.wrap_iv,
    wrap_salt = excluded.wrap_salt,
    updated_at = excluded.updated_at;
end;
$$;
revoke all on function public.set_my_encryption_key(jsonb, text, text, text) from public, anon;
grant execute on function public.set_my_encryption_key(jsonb, text, text, text) to authenticated;

commit;
