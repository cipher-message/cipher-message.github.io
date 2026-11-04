-- Pre-auth signup abuse guard. Store keyed address digests only; browser roles
-- cannot read the counters or execute the rate-limit RPC.
begin;

create table if not exists private.signup_ip_rate_limits (
  ip_hash text primary key,
  minute_bucket timestamptz not null,
  minute_count integer not null,
  hour_bucket timestamptz not null,
  hour_count integer not null
);
alter table private.signup_ip_rate_limits enable row level security;
revoke all on private.signup_ip_rate_limits from public, anon, authenticated;

create or replace function public.consume_signup_ip_rate_limit(p_ip_hash text)
returns void language plpgsql security definer set search_path = ''
as $$
declare v_now timestamptz := clock_timestamp(); v_minute timestamptz; v_hour timestamptz;
begin
  if p_ip_hash is null or p_ip_hash !~ '^[0-9a-f]{64}$' then
    raise exception 'invalid rate key' using errcode = '22023';
  end if;
  v_minute := to_timestamp(floor(extract(epoch from v_now) / 60) * 60);
  v_hour := to_timestamp(floor(extract(epoch from v_now) / 3600) * 3600);
  insert into private.signup_ip_rate_limits as r
    (ip_hash, minute_bucket, minute_count, hour_bucket, hour_count)
  values (p_ip_hash, v_minute, 1, v_hour, 1)
  on conflict (ip_hash) do update set
    minute_count = case when r.minute_bucket = excluded.minute_bucket then r.minute_count + 1 else 1 end,
    minute_bucket = excluded.minute_bucket,
    hour_count = case when r.hour_bucket = excluded.hour_bucket then r.hour_count + 1 else 1 end,
    hour_bucket = excluded.hour_bucket
  where (r.minute_bucket <> excluded.minute_bucket or r.minute_count < 5)
    and (r.hour_bucket <> excluded.hour_bucket or r.hour_count < 30);
  if not found then raise exception 'signup rate limit exceeded' using errcode = 'P0001'; end if;
end;
$$;
revoke all on function public.consume_signup_ip_rate_limit(text) from public, anon, authenticated;
grant execute on function public.consume_signup_ip_rate_limit(text) to service_role;

commit;
