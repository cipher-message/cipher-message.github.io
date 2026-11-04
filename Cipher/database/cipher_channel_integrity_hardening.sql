-- Protect channel ownership and membership security fields while preserving
-- per-member preferences and shared background/disappearing-message controls.
begin;

create or replace function private.guard_channel_update()
returns trigger language plpgsql security definer set search_path = ''
as $$
declare v_uid uuid := (select auth.uid());
begin
  if new.id is distinct from old.id or new.type is distinct from old.type
     or new.created_at is distinct from old.created_at
     or (new.created_by is distinct from old.created_by and not (new.created_by is null and old.created_by = v_uid)) then
    raise exception 'channel identity is immutable' using errcode = '42501';
  end if;
  if (new.name is distinct from old.name or new.topic is distinct from old.topic
      or new.is_public is distinct from old.is_public or new.ultra_private is distinct from old.ultra_private)
     and not exists (
       select 1 from public.channel_members cm
       where cm.channel_id = old.id and cm.user_id = v_uid and cm.role = 'owner'
     ) then
    raise exception 'channel owner permission required' using errcode = '42501';
  end if;
  if coalesce(octet_length(new.name), 0) > 128 or coalesce(octet_length(new.topic), 0) > 1000 then
    raise exception 'channel details too large' using errcode = '22023';
  end if;
  if new.disappear_seconds is distinct from old.disappear_seconds
     and new.disappear_seconds is not null
     and new.disappear_seconds not in (86400, 604800, 7776000) then
    raise exception 'invalid disappearing-message interval' using errcode = '22023';
  end if;
  if new.background is distinct from old.background and new.background is not null then
    if jsonb_typeof(new.background) <> 'object' or pg_column_size(new.background) > 8192 then
      raise exception 'invalid channel background' using errcode = '22023';
    end if;
    if new.background ->> 'type' not in ('none', 'preset', 'image') then
      raise exception 'invalid channel background type' using errcode = '22023';
    end if;
    if new.background ->> 'type' = 'image'
       and left(new.background ->> 'path', length(v_uid::text || '/' || old.id::text || '-')) <> v_uid::text || '/' || old.id::text || '-' then
      raise exception 'invalid channel background path' using errcode = '42501';
    end if;
  end if;
  return new;
end;
$$;
revoke all on function private.guard_channel_update() from public, anon, authenticated;
drop trigger if exists cipher_guard_channels_update on public.channels;
create trigger cipher_guard_channels_update before update on public.channels
for each row execute function private.guard_channel_update();

create or replace function private.guard_channel_member_update()
returns trigger language plpgsql security definer set search_path = ''
as $$
begin
  if new.channel_id is distinct from old.channel_id or new.user_id is distinct from old.user_id
     or new.role is distinct from old.role or new.joined_at is distinct from old.joined_at then
    raise exception 'membership identity and role are immutable' using errcode = '42501';
  end if;
  if new.last_read_at > clock_timestamp() then new.last_read_at := clock_timestamp(); end if;
  if new.background is not null and pg_column_size(new.background) > 16384 then
    raise exception 'member settings too large' using errcode = '22001';
  end if;
  return new;
end;
$$;
revoke all on function private.guard_channel_member_update() from public, anon, authenticated;
drop trigger if exists cipher_guard_members_update on public.channel_members;
create trigger cipher_guard_members_update before update on public.channel_members
for each row execute function private.guard_channel_member_update();

drop policy if exists "channels_update" on public.channels;
create policy "channels_update" on public.channels for update to authenticated
using (is_channel_member(id)) with check (is_channel_member(id));
drop policy if exists "members_update_self" on public.channel_members;
create policy "members_update_self" on public.channel_members for update to authenticated
using (user_id = (select auth.uid()) and is_channel_member(channel_id))
with check (user_id = (select auth.uid()) and is_channel_member(channel_id));

commit;
