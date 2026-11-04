-- Enforce status lifetime, owner, payload, visibility, and per-user story limits.
begin;

create or replace function private.guard_status_insert()
returns trigger language plpgsql security definer set search_path = ''
as $$
declare v_uid uuid := (select auth.uid()); v_now timestamptz := clock_timestamp();
begin
  if tg_table_name = 'statuses' then
    if v_uid is not null then perform private.consume_action_limit(v_uid, 'statuses', 600, 3, 86400, 8); end if;
    if new.type not in ('text', 'image') then raise exception 'invalid status type' using errcode = '22023'; end if;
    if new.type = 'text' and (new.text_content is null or octet_length(new.text_content) > 2000) then
      raise exception 'invalid status text' using errcode = '22023';
    end if;
    if new.bg_color is not null and new.bg_color !~ '^#[0-9a-fA-F]{6}$' then
      raise exception 'invalid status color' using errcode = '22023';
    end if;
    if new.type = 'image' and (new.storage_path is null or split_part(new.storage_path, '/', 1) <> 'status'
       or split_part(new.storage_path, '/', 2) <> new.user_id::text) then
      raise exception 'invalid status media path' using errcode = '22023';
    end if;
    new.created_at := v_now;
    new.expires_at := v_now + interval '24 hours';
  else
    if v_uid is not null then perform private.consume_action_limit(v_uid, 'status_views', 60, 30, 86400, 500); end if;
    new.viewed_at := v_now;
  end if;
  return new;
end;
$$;
revoke all on function private.guard_status_insert() from public, anon, authenticated;

drop trigger if exists cipher_guard_statuses_insert on public.statuses;
create trigger cipher_guard_statuses_insert before insert on public.statuses
for each row execute function private.guard_status_insert();
drop trigger if exists cipher_guard_status_views_insert on public.status_views;
create trigger cipher_guard_status_views_insert before insert on public.status_views
for each row execute function private.guard_status_insert();

drop policy if exists "select visible statuses" on public.statuses;
create policy "select visible statuses" on public.statuses for select to authenticated using (
  expires_at > now() and (
    user_id = (select auth.uid()) or (
      exists (
        select 1 from public.channel_members mine
        join public.channel_members them on them.channel_id = mine.channel_id
        join public.channels c on c.id = mine.channel_id
        where mine.user_id = (select auth.uid()) and them.user_id = statuses.user_id and c.type = 'dm'
      )
      and not exists (
        select 1 from public.blocks b
        where (b.blocker_id = (select auth.uid()) and b.blocked_id = statuses.user_id)
           or (b.blocker_id = statuses.user_id and b.blocked_id = (select auth.uid()))
      )
    )
  )
);
drop policy if exists "insert own statuses" on public.statuses;
create policy "insert own statuses" on public.statuses for insert to authenticated
with check (user_id = (select auth.uid()));
drop policy if exists "delete own statuses" on public.statuses;
create policy "delete own statuses" on public.statuses for delete to authenticated
using (user_id = (select auth.uid()));

drop policy if exists "insert own views" on public.status_views;
create policy "insert own views" on public.status_views for insert to authenticated
with check (
  viewer_id = (select auth.uid()) and exists (
    select 1 from public.statuses s
    where s.id = status_id and s.user_id <> (select auth.uid()) and s.expires_at > now()
  )
);
drop policy if exists "select relevant views" on public.status_views;
create policy "select relevant views" on public.status_views for select to authenticated using (
  viewer_id = (select auth.uid()) or exists (
    select 1 from public.statuses s where s.id = status_id and s.user_id = (select auth.uid())
  )
);

commit;
