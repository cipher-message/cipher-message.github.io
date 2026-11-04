-- ICE negotiation legitimately emits several signals per call. Keep stricter
-- limits for call control while allowing bounded candidate bursts.
begin;

alter table private.call_rate_limits add column if not exists action text not null default 'control';
alter table private.call_rate_limits drop constraint if exists call_rate_limits_pkey;
alter table private.call_rate_limits add constraint call_rate_limits_pkey primary key (caller_id, peer_id, action);

create or replace function private.consume_call_rate_limit(p_caller uuid, p_peer uuid, p_action text)
returns void language plpgsql security definer set search_path = ''
as $$
declare
  v_now timestamptz := clock_timestamp();
  v_short timestamptz;
  v_long timestamptz;
  v_short_max integer;
  v_long_max integer;
begin
  if p_action not in ('control', 'ice') then raise exception 'invalid call signal class' using errcode = '22023'; end if;
  v_short_max := case when p_action = 'ice' then 40 else 3 end;
  v_long_max := case when p_action = 'ice' then 240 else 15 end;
  v_short := to_timestamp(floor(extract(epoch from v_now) / 10) * 10);
  v_long := to_timestamp(floor(extract(epoch from v_now) / 60) * 60);
  insert into private.call_rate_limits as r
    (caller_id, peer_id, action, short_bucket, short_count, long_bucket, long_count)
  values (p_caller, p_peer, p_action, v_short, 1, v_long, 1)
  on conflict (caller_id, peer_id, action) do update set
    short_count = case when r.short_bucket = excluded.short_bucket then r.short_count + 1 else 1 end,
    short_bucket = excluded.short_bucket,
    long_count = case when r.long_bucket = excluded.long_bucket then r.long_count + 1 else 1 end,
    long_bucket = excluded.long_bucket
  where (r.short_bucket <> excluded.short_bucket or r.short_count < v_short_max)
    and (r.long_bucket <> excluded.long_bucket or r.long_count < v_long_max);
  if not found then raise exception 'call rate limit exceeded' using errcode = 'P0001'; end if;
end;
$$;
revoke all on function private.consume_call_rate_limit(uuid, uuid, text) from public, anon, authenticated;
drop function private.consume_call_rate_limit(uuid, uuid);

create or replace function public.send_call_signal(peer_id uuid, payload jsonb)
returns void language plpgsql security definer set search_path = ''
as $$
declare
  me uuid := (select auth.uid()); signal_type text; clean_payload jsonb;
  profile_name text; profile_avatar text; dm_channel uuid;
begin
  if me is null then raise exception 'not authenticated' using errcode = '42501'; end if;
  if peer_id is null or peer_id = me or payload is null or jsonb_typeof(payload) <> 'object' or pg_column_size(payload) > 32768 then raise exception 'invalid call signal' using errcode = '22023'; end if;
  signal_type := payload ->> 'type';
  if signal_type is null or signal_type not in ('offer','answer','ice','hangup','reject') then raise exception 'invalid call signal' using errcode = '22023'; end if;
  if signal_type in ('offer','answer') and (jsonb_typeof(payload -> 'sdp') <> 'object' or payload -> 'sdp' ->> 'type' <> signal_type or payload -> 'sdp' ->> 'sdp' is null or length(payload -> 'sdp' ->> 'sdp') > 20000) then raise exception 'invalid call description' using errcode = '22023'; end if;
  if signal_type = 'ice' and (payload -> 'candidate' is null or jsonb_typeof(payload -> 'candidate') <> 'object' or pg_column_size(payload -> 'candidate') > 8192 or length(coalesce(payload -> 'candidate' ->> 'candidate','')) > 4096 or length(coalesce(payload -> 'candidate' ->> 'sdpMid','')) > 256) then raise exception 'invalid call candidate' using errcode = '22023'; end if;
  if signal_type = 'offer' and ((payload -> 'dmChannelId') is null or (payload ? 'video' and jsonb_typeof(payload -> 'video') <> 'boolean')) then raise exception 'invalid call options' using errcode = '22023'; end if;
  select c.id into dm_channel from public.channels c
  join public.channel_members a on a.channel_id = c.id and a.user_id = me
  join public.channel_members b on b.channel_id = c.id and b.user_id = peer_id
  where c.type = 'dm' and (signal_type <> 'offer' or c.id::text = payload ->> 'dmChannelId')
  order by c.created_at desc limit 1;
  if dm_channel is null or exists(select 1 from public.blocks x where (x.blocker_id=me and x.blocked_id=peer_id) or (x.blocker_id=peer_id and x.blocked_id=me)) then raise exception 'call is not allowed' using errcode = '42501'; end if;

  perform private.consume_call_rate_limit(me, peer_id, case when signal_type='ice' then 'ice' else 'control' end);
  select p.display_name,p.avatar_url into profile_name,profile_avatar from public.profiles p where p.id=me;
  if signal_type in ('offer','answer') then
    clean_payload := jsonb_build_object('type',signal_type,'sdp',payload -> 'sdp');
    if signal_type='offer' then clean_payload := clean_payload || jsonb_build_object('video',coalesce((payload ->> 'video')::boolean,false),'dmChannelId',dm_channel); end if;
  elsif signal_type='ice' then clean_payload := jsonb_build_object('type','ice','candidate',payload -> 'candidate');
  else clean_payload := jsonb_build_object('type',signal_type,'reason',left(coalesce(payload ->> 'reason',''),64));
  end if;
  perform realtime.send(clean_payload || jsonb_build_object('from',me::text,'fromName',profile_name,'fromAvatar',profile_avatar),'call-signal','calls:' || peer_id::text,true);
end;
$$;
revoke all on function public.send_call_signal(uuid, jsonb) from public, anon;
grant execute on function public.send_call_signal(uuid, jsonb) to authenticated;

commit;
