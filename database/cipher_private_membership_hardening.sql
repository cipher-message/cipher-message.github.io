-- Focused first-stage fix: prevent self-joining private channels and keep DMs
-- limited to two participants. This is intentionally separate from the wider
-- security migration so it can be reviewed and rolled back independently.
begin;

create schema if not exists private;
revoke all on schema private from public, anon, authenticated;

create or replace function private.guard_dm_membership_limit()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_type text;
  v_count integer;
begin
  select c.type into v_type
  from public.channels c
  where c.id = new.channel_id
  for update;

  if v_type = 'dm' then
    select count(*) into v_count
    from public.channel_members cm
    where cm.channel_id = new.channel_id;
    if v_count >= 2 then
      raise exception 'direct messages can have only two members' using errcode = '42501';
    end if;
  end if;
  return new;
end;
$$;
revoke all on function private.guard_dm_membership_limit() from public, anon, authenticated;

drop trigger if exists guard_dm_membership_limit on public.channel_members;
create trigger guard_dm_membership_limit
before insert on public.channel_members
for each row execute function private.guard_dm_membership_limit();

drop policy if exists "members_insert" on public.channel_members;
create policy "members_insert" on public.channel_members
for insert to authenticated
with check (
  (
    user_id = (select auth.uid())
    and role = 'member'
    and exists (
      select 1 from public.channels c
      where c.id = channel_id and c.type = 'group' and c.is_public = true
    )
  )
  or exists (
    select 1 from public.channels c
    where c.id = channel_id
      and c.created_by = (select auth.uid())
      and (
        (user_id = (select auth.uid()) and role = 'owner')
        or (user_id <> (select auth.uid()) and role = 'member')
      )
  )
);

commit;

-- Rollback if required:
-- begin;
-- drop policy if exists "members_insert" on public.channel_members;
-- create policy "members_insert" on public.channel_members for insert to public
--   with check ((user_id = (select auth.uid())) or exists (
--     select 1 from public.channels c
--     where c.id = channel_id and c.created_by = (select auth.uid())
--   ));
-- drop trigger if exists guard_dm_membership_limit on public.channel_members;
-- drop function if exists private.guard_dm_membership_limit();
-- commit;
