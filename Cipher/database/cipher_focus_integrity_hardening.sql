-- Focus sessions are controlled by their starter; participants may only join,
-- leave, and update their own server-timed participation row.
begin;

create or replace function private.guard_focus_integrity()
returns trigger language plpgsql security definer set search_path = ''
as $$
declare v_now timestamptz := clock_timestamp(); v_ends_at timestamptz;
begin
  if tg_table_name = 'focus_sessions' then
    if new.duration_seconds is null or new.duration_seconds < 300 or new.duration_seconds > 7200
       or coalesce(octet_length(new.label), 0) > 128 then
      raise exception 'invalid focus session settings' using errcode = '22023';
    end if;
    if tg_op = 'INSERT' then
      new.started_at := v_now;
      new.created_at := v_now;
      new.ends_at := v_now + make_interval(secs => new.duration_seconds);
      new.ended_early := false;
      return new;
    end if;
    if new.id is distinct from old.id or new.channel_id is distinct from old.channel_id
       or new.started_by is distinct from old.started_by
       or new.duration_seconds is distinct from old.duration_seconds
       or new.started_at is distinct from old.started_at
       or new.ends_at is distinct from old.ends_at
       or new.created_at is distinct from old.created_at
       or new.label is distinct from old.label
       or old.ended_early or not new.ended_early then
      raise exception 'invalid focus session transition' using errcode = '42501';
    end if;
    return new;
  end if;

  if tg_op = 'INSERT' then
    select fs.ends_at into v_ends_at from public.focus_sessions fs where fs.id = new.session_id;
    if v_ends_at is null or v_ends_at <= v_now then
      raise exception 'focus session is no longer active' using errcode = '42501';
    end if;
    new.joined_at := v_now;
    new.left_at := null;
    new.focused_seconds := null;
    return new;
  end if;

  if new.session_id is distinct from old.session_id or new.user_id is distinct from old.user_id then
    raise exception 'participant identity is immutable' using errcode = '42501';
  end if;
  if old.left_at is null and new.left_at is not null then
    select fs.ends_at into v_ends_at from public.focus_sessions fs where fs.id = new.session_id;
    v_now := least(v_now, coalesce(v_ends_at, v_now));
    new.joined_at := old.joined_at;
    new.left_at := v_now;
    new.focused_seconds := greatest(0, floor(extract(epoch from v_now - old.joined_at))::integer);
  elsif old.left_at is not null and new.left_at is null then
    select fs.ends_at into v_ends_at from public.focus_sessions fs where fs.id = new.session_id;
    if v_ends_at is null or v_ends_at <= v_now then
      raise exception 'focus session is no longer active' using errcode = '42501';
    end if;
    new.joined_at := v_now;
    new.focused_seconds := null;
  elsif new.joined_at is distinct from old.joined_at or new.left_at is distinct from old.left_at
        or new.focused_seconds is distinct from old.focused_seconds then
    raise exception 'invalid focus participant transition' using errcode = '42501';
  end if;
  return new;
end;
$$;
revoke all on function private.guard_focus_integrity() from public, anon, authenticated;

drop trigger if exists cipher_guard_focus_sessions_insert on public.focus_sessions;
create trigger cipher_guard_focus_sessions_insert before insert on public.focus_sessions
for each row execute function private.guard_focus_integrity();
drop trigger if exists cipher_guard_focus_sessions_update on public.focus_sessions;
create trigger cipher_guard_focus_sessions_update before update on public.focus_sessions
for each row execute function private.guard_focus_integrity();
drop trigger if exists cipher_guard_focus_participants_insert on public.focus_participants;
create trigger cipher_guard_focus_participants_insert before insert on public.focus_participants
for each row execute function private.guard_focus_integrity();
drop trigger if exists cipher_guard_focus_participants_update on public.focus_participants;
create trigger cipher_guard_focus_participants_update before update on public.focus_participants
for each row execute function private.guard_focus_integrity();

drop policy if exists "focus_sessions_update" on public.focus_sessions;
create policy "focus_sessions_update" on public.focus_sessions for update to authenticated
using (started_by = (select auth.uid()) and is_channel_member(channel_id))
with check (started_by = (select auth.uid()) and is_channel_member(channel_id));
drop policy if exists "focus_participants_insert" on public.focus_participants;
create policy "focus_participants_insert" on public.focus_participants for insert to authenticated
with check (user_id = (select auth.uid()) and exists (
  select 1 from public.focus_sessions fs
  where fs.id = session_id and fs.ends_at > now() and not fs.ended_early and is_channel_member(fs.channel_id)
));
drop policy if exists "focus_participants_update" on public.focus_participants;
create policy "focus_participants_update" on public.focus_participants for update to authenticated
using (user_id = (select auth.uid()))
with check (user_id = (select auth.uid()) and exists (
  select 1 from public.focus_sessions fs where fs.id = session_id and is_channel_member(fs.channel_id)
));

commit;
