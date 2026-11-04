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
