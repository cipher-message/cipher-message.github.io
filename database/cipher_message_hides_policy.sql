-- Keep per-user hidden-message state private and tied to a visible conversation.
begin;

drop policy if exists "select own hides" on public.message_hides;
create policy "select own hides" on public.message_hides for select to authenticated
using (user_id = (select auth.uid()));
drop policy if exists "insert own hides" on public.message_hides;
create policy "insert own hides" on public.message_hides for insert to authenticated
with check (user_id = (select auth.uid()) and exists (
  select 1 from public.messages m where m.id = message_id and is_channel_member(m.channel_id)
));
drop policy if exists "delete own hides" on public.message_hides;
create policy "delete own hides" on public.message_hides for delete to authenticated
using (user_id = (select auth.uid()));

commit;
