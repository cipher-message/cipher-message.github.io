-- Atomic per-user message throttling. Boundaries are transaction-safe and the
-- rate table is inaccessible to browser roles.
begin;

create table if not exists private.action_rate_limits (
  user_id uuid not null references auth.users(id) on delete cascade,
  action text not null,
  short_bucket timestamptz not null,
  short_count integer not null,
  long_bucket timestamptz not null,
  long_count integer not null,
  primary key (user_id, action)
);
alter table private.action_rate_limits enable row level security;
revoke all on private.action_rate_limits from public, anon, authenticated;

create or replace function private.consume_action_limit(
  p_uid uuid, p_action text, p_short_seconds integer, p_short_max integer,
  p_long_seconds integer, p_long_max integer
) returns void language plpgsql security definer set search_path = ''
as $$
declare v_now timestamptz := clock_timestamp(); v_short timestamptz; v_long timestamptz;
begin
  if p_uid is null or p_action is null or p_short_seconds < 1
     or p_long_seconds < p_short_seconds or p_short_max < 1 or p_long_max < p_short_max then
    raise exception 'invalid rate configuration' using errcode = '22023';
  end if;
  v_short := to_timestamp(floor(extract(epoch from v_now) / p_short_seconds) * p_short_seconds);
  v_long := to_timestamp(floor(extract(epoch from v_now) / p_long_seconds) * p_long_seconds);
  insert into private.action_rate_limits as r
    (user_id, action, short_bucket, short_count, long_bucket, long_count)
  values (p_uid, p_action, v_short, 1, v_long, 1)
  on conflict (user_id, action) do update set
    short_count = case when r.short_bucket = excluded.short_bucket then r.short_count + 1 else 1 end,
    short_bucket = excluded.short_bucket,
    long_count = case when r.long_bucket = excluded.long_bucket then r.long_count + 1 else 1 end,
    long_bucket = excluded.long_bucket
  where (r.short_bucket <> excluded.short_bucket or r.short_count < p_short_max)
    and (r.long_bucket <> excluded.long_bucket or r.long_count < p_long_max);
  if not found then raise exception 'rate limit exceeded for %', p_action using errcode = 'P0001'; end if;
end;
$$;
revoke all on function private.consume_action_limit(uuid, text, integer, integer, integer, integer) from public, anon, authenticated;

create or replace function private.limit_message_inserts()
returns trigger language plpgsql security definer set search_path = ''
as $$
declare v_uid uuid := (select auth.uid());
begin
  if v_uid is not null then
    perform private.consume_action_limit(v_uid, 'messages', 10, 8, 60, 40);
  end if;
  return new;
end;
$$;
revoke all on function private.limit_message_inserts() from public, anon, authenticated;
drop trigger if exists limit_message_inserts on public.messages;
create trigger limit_message_inserts before insert on public.messages
for each row execute function private.limit_message_inserts();

commit;
