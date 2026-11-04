-- Server-enforced Cipher AI ban list.
-- Manage rows in Supabase Dashboard. The Edge Function reads each caller's row
-- on every request; no in-memory ban cache is used.

create table if not exists public.cipher_ai_bans (
  user_id uuid primary key references auth.users(id) on delete cascade,
  ai_banned boolean not null default false,
  ban_reason text not null default '',
  updated_at timestamptz not null default now(),
  constraint cipher_ai_bans_reason_length check (char_length(ban_reason) <= 500),
  constraint cipher_ai_bans_reason_required check (not ai_banned or length(btrim(ban_reason)) > 0)
);

alter table public.cipher_ai_bans enable row level security;
revoke all on table public.cipher_ai_bans from public, anon, authenticated;
grant select on table public.cipher_ai_bans to service_role;

comment on table public.cipher_ai_bans is
  'Server-enforced Cipher AI bans. Manage via Supabase Dashboard; only the service role can read rows through the API.';
comment on column public.cipher_ai_bans.user_id is
  'Auth user UUID to ban or unban. Find it in Authentication > Users.';
comment on column public.cipher_ai_bans.ai_banned is
  'Set true to immediately block Cipher AI requests; false to lift the ban.';
comment on column public.cipher_ai_bans.ban_reason is
  'Reason shown to the user when ai_banned is true (up to 500 characters).';

create or replace function private.touch_cipher_ai_ban_updated_at()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  new.updated_at := pg_catalog.now();
  return new;
end;
$$;

revoke all on function private.touch_cipher_ai_ban_updated_at() from public, anon, authenticated;

drop trigger if exists cipher_ai_bans_updated_at on public.cipher_ai_bans;
create trigger cipher_ai_bans_updated_at
before update on public.cipher_ai_bans
for each row execute function private.touch_cipher_ai_ban_updated_at();
