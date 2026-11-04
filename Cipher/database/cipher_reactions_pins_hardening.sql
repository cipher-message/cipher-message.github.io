-- Restore deliberate message reaction/star access and bind pin creation to the
-- acting member and the exact channel containing the message.
begin;

create or replace function private.limit_social_inserts()
returns trigger language plpgsql security definer set search_path = ''
as $$
declare v_uid uuid := (select auth.uid()); v_action text;
begin
  if tg_table_name in ('reactions', 'message_reactions') then
    if new.emoji is null or length(new.emoji) < 1 or octet_length(new.emoji) > 64 then
      raise exception 'invalid reaction' using errcode = '22023';
    end if;
    v_action := 'reactions';
    if v_uid is not null then perform private.consume_action_limit(v_uid, v_action, 10, 12, 60, 60); end if;
  elsif tg_table_name = 'message_stars' then
    if v_uid is not null then perform private.consume_action_limit(v_uid, 'message_stars', 10, 20, 86400, 100); end if;
  elsif tg_table_name = 'pins' then
    if v_uid is not null then perform private.consume_action_limit(v_uid, 'pins', 10, 20, 86400, 100); end if;
  end if;
  return new;
end;
$$;
revoke all on function private.limit_social_inserts() from public, anon, authenticated;
drop trigger if exists cipher_guard_reactions_insert on public.reactions;
create trigger cipher_guard_reactions_insert before insert on public.reactions
for each row execute function private.limit_social_inserts();
drop trigger if exists cipher_guard_message_reactions_insert on public.message_reactions;
create trigger cipher_guard_message_reactions_insert before insert on public.message_reactions
for each row execute function private.limit_social_inserts();
drop trigger if exists limit_message_stars on public.message_stars;
create trigger limit_message_stars before insert on public.message_stars
for each row execute function private.limit_social_inserts();
drop trigger if exists limit_pins on public.pins;
create trigger limit_pins before insert on public.pins
for each row execute function private.limit_social_inserts();

drop policy if exists "message_reactions_select" on public.message_reactions;
create policy "message_reactions_select" on public.message_reactions for select to authenticated
using (exists (select 1 from public.messages m where m.id = message_id and is_channel_member(m.channel_id)));
drop policy if exists "message_reactions_insert" on public.message_reactions;
create policy "message_reactions_insert" on public.message_reactions for insert to authenticated
with check (user_id = (select auth.uid()) and exists (
  select 1 from public.messages m where m.id = message_id and is_channel_member(m.channel_id)
));
drop policy if exists "message_reactions_delete" on public.message_reactions;
create policy "message_reactions_delete" on public.message_reactions for delete to authenticated
using (user_id = (select auth.uid()));

drop policy if exists "message_stars_select" on public.message_stars;
create policy "message_stars_select" on public.message_stars for select to authenticated
using (user_id = (select auth.uid()));
drop policy if exists "message_stars_insert" on public.message_stars;
create policy "message_stars_insert" on public.message_stars for insert to authenticated
with check (user_id = (select auth.uid()) and exists (
  select 1 from public.messages m where m.id = message_id and is_channel_member(m.channel_id)
));
drop policy if exists "message_stars_delete" on public.message_stars;
create policy "message_stars_delete" on public.message_stars for delete to authenticated
using (user_id = (select auth.uid()));

drop policy if exists "pins_insert" on public.pins;
create policy "pins_insert" on public.pins for insert to authenticated
with check (pinned_by = (select auth.uid()) and is_channel_member(channel_id) and exists (
  select 1 from public.messages m where m.id = pins.message_id and m.channel_id = pins.channel_id
));

commit;
