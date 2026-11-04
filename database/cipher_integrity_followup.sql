-- Close nullable-state edge cases in focus transitions and message replies.
begin;

create or replace function private.guard_focus_end_transition()
returns trigger language plpgsql security definer set search_path = ''
as $$
begin
  if old.ended_early is true or new.ended_early is not true then
    raise exception 'invalid focus session transition' using errcode = '42501';
  end if;
  return new;
end;
$$;
revoke all on function private.guard_focus_end_transition() from public, anon, authenticated;
drop trigger if exists guard_focus_end_transition on public.focus_sessions;
create trigger guard_focus_end_transition before update on public.focus_sessions
for each row execute function private.guard_focus_end_transition();

create or replace function private.guard_message_reply_target()
returns trigger language plpgsql security definer set search_path = ''
as $$
begin
  if new.reply_to is not null and not exists (
    select 1 from public.messages m
    where m.id = new.reply_to and m.channel_id = new.channel_id
  ) then
    raise exception 'reply target unavailable' using errcode = '23503';
  end if;
  return new;
end;
$$;
revoke all on function private.guard_message_reply_target() from public, anon, authenticated;
drop trigger if exists guard_message_reply_target on public.messages;
create trigger guard_message_reply_target before insert or update of reply_to, channel_id on public.messages
for each row execute function private.guard_message_reply_target();

commit;
