-- Protect message identity and bound user-controlled message payloads.
begin;

create or replace function private.guard_message_integrity()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare v_now timestamptz := clock_timestamp();
begin
  if new.content is not null and octet_length(new.content) > 16384 then
    raise exception 'message too large' using errcode = '22001';
  end if;
  if new.ciphertext is not null and octet_length(new.ciphertext) > 65536 then
    raise exception 'encrypted message too large' using errcode = '22001';
  end if;
  if new.iv is not null and octet_length(new.iv) > 256 then
    raise exception 'invalid encryption metadata' using errcode = '22023';
  end if;
  if new.encrypted_keys is not null and
     (jsonb_typeof(new.encrypted_keys) <> 'object' or pg_column_size(new.encrypted_keys) > 32768) then
    raise exception 'invalid encryption metadata' using errcode = '22023';
  end if;

  if tg_op = 'INSERT' then
    new.edited_at := null;
    if new.reply_to is not null and not exists (
      select 1 from public.messages m
      where m.id = new.reply_to and m.channel_id = new.channel_id
    ) then
      raise exception 'reply target unavailable' using errcode = '23503';
    end if;
    return new;
  end if;

  if new.id is distinct from old.id
     or new.channel_id is distinct from old.channel_id
     or new.created_at is distinct from old.created_at
     or new.expires_at is distinct from old.expires_at
     or new.forwarded is distinct from old.forwarded
     or (new.sender_id is distinct from old.sender_id and
         not (new.sender_id is null and old.sender_id = (select auth.uid()))) then
    raise exception 'message identity is immutable' using errcode = '42501';
  end if;
  new.edited_at := case
    when new.content is distinct from old.content
      or new.ciphertext is distinct from old.ciphertext
      or new.iv is distinct from old.iv
      or new.encrypted_keys is distinct from old.encrypted_keys
    then v_now else old.edited_at end;
  return new;
end;
$$;
revoke all on function private.guard_message_integrity() from public, anon, authenticated;

drop trigger if exists cipher_guard_messages_insert on public.messages;
create trigger cipher_guard_messages_insert before insert on public.messages
for each row execute function private.guard_message_integrity();
drop trigger if exists cipher_guard_messages_update on public.messages;
create trigger cipher_guard_messages_update before update on public.messages
for each row execute function private.guard_message_integrity();

drop policy if exists "messages_update" on public.messages;
create policy "messages_update" on public.messages for update to authenticated
using (sender_id = (select auth.uid()) and is_channel_member(channel_id))
with check (sender_id = (select auth.uid()) and is_channel_member(channel_id));

commit;
