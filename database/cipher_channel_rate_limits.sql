-- Bound channel creation, public joins, and member invitations per user.
begin;

create or replace function private.limit_channel_actions()
returns trigger language plpgsql security definer set search_path = ''
as $$
declare v_uid uuid := (select auth.uid());
begin
  if v_uid is null then return new; end if;
  if tg_table_name = 'channels' then
    perform private.consume_action_limit(v_uid, 'channels', 600, 5, 86400, 20);
  elsif new.user_id = v_uid then
    perform private.consume_action_limit(v_uid, 'channel_joins', 600, 10, 86400, 40);
  else
    perform private.consume_action_limit(v_uid, 'channel_invites', 600, 10, 86400, 100);
  end if;
  return new;
end;
$$;
revoke all on function private.limit_channel_actions() from public, anon, authenticated;
drop trigger if exists limit_channel_creates on public.channels;
create trigger limit_channel_creates before insert on public.channels
for each row execute function private.limit_channel_actions();
drop trigger if exists limit_channel_memberships on public.channel_members;
create trigger limit_channel_memberships before insert on public.channel_members
for each row execute function private.limit_channel_actions();

commit;
