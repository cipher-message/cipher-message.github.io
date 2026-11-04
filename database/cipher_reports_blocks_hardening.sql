-- Prevent self-targeted reports/blocks and bound report flooding.
begin;

create or replace function private.guard_report_insert()
returns trigger language plpgsql security definer set search_path = ''
as $$
declare v_uid uuid := (select auth.uid());
begin
  if new.reporter_id is distinct from v_uid or new.reported_id is null or new.reported_id = v_uid
     or new.reason is null or length(new.reason) < 1 or octet_length(new.reason) > 1000 then
    raise exception 'invalid report details' using errcode = '22023';
  end if;
  if v_uid is not null then perform private.consume_action_limit(v_uid, 'reports', 3600, 2, 86400, 5); end if;
  new.created_at := clock_timestamp();
  return new;
end;
$$;
revoke all on function private.guard_report_insert() from public, anon, authenticated;
drop trigger if exists cipher_guard_reports_insert on public.reports;
create trigger cipher_guard_reports_insert before insert on public.reports
for each row execute function private.guard_report_insert();

drop policy if exists "reports_insert" on public.reports;
create policy "reports_insert" on public.reports for insert to authenticated
with check (reporter_id = (select auth.uid()) and reported_id <> (select auth.uid()));

drop policy if exists "blocks_insert" on public.blocks;
create policy "blocks_insert" on public.blocks for insert to authenticated
with check (blocker_id = (select auth.uid()) and blocked_id <> (select auth.uid()));

commit;
