-- Cipher group voice/video calling + live screen sharing backend.
-- Idempotent source-of-truth for the group-call objects used by App/Cipher.html.
-- Privileged implementation functions stay in the private schema; public RPCs are
-- SECURITY INVOKER wrappers so every request still executes with the caller's identity.

begin;

create schema if not exists private;

create table if not exists public.group_calls (
  id uuid primary key default gen_random_uuid(),
  channel_id uuid not null references public.channels(id),
  started_by uuid references auth.users(id),
  with_video boolean not null default false,
  started_at timestamptz not null default now(),
  ended_at timestamptz
);

create table if not exists public.group_call_participants (
  call_id uuid not null references public.group_calls(id),
  channel_id uuid not null references public.channels(id),
  user_id uuid not null references auth.users(id),
  session_id uuid not null default gen_random_uuid(),
  with_video boolean not null default false,
  muted boolean not null default false,
  cam_on boolean not null default false,
  sharing boolean not null default false,
  share_audio boolean not null default false,
  joined_at timestamptz not null default now(),
  last_seen timestamptz not null default now(),
  primary key (call_id, user_id)
);

create table if not exists private.group_call_rate_limits (
  user_id uuid not null references auth.users(id),
  action text not null,
  bucket timestamptz not null,
  n integer not null,
  primary key (user_id, action)
);

alter table public.group_calls enable row level security;
alter table public.group_call_participants enable row level security;
alter table private.group_call_rate_limits enable row level security;

create index if not exists group_calls_ended_idx
  on public.group_calls(ended_at)
  where ended_at is not null;

create unique index if not exists group_calls_one_active
  on public.group_calls(channel_id)
  where ended_at is null;

create index if not exists group_call_participants_channel_idx
  on public.group_call_participants(channel_id);

create index if not exists group_call_participants_user_id_idx
  on public.group_call_participants(user_id);

create index if not exists group_calls_started_by_idx
  on public.group_calls(started_by);

revoke all on public.group_calls from anon, authenticated;
revoke all on public.group_call_participants from anon, authenticated;
grant select on public.group_calls to authenticated;
grant select on public.group_call_participants to authenticated;
revoke all on private.group_call_rate_limits from public, anon, authenticated;

drop policy if exists group_calls_select_members on public.group_calls;
create policy group_calls_select_members
on public.group_calls
for select to authenticated
using (
  exists (
    select 1
    from public.channel_members m
    where m.channel_id = group_calls.channel_id
      and m.user_id = (select auth.uid())
  )
);

drop policy if exists group_call_participants_select_members on public.group_call_participants;
create policy group_call_participants_select_members
on public.group_call_participants
for select to authenticated
using (
  exists (
    select 1
    from public.channel_members m
    where m.channel_id = group_call_participants.channel_id
      and m.user_id = (select auth.uid())
  )
);

create or replace function private.gc_consume(
  p_uid uuid,
  p_action text,
  p_window integer,
  p_max integer
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_b timestamptz := to_timestamp(
    floor(extract(epoch from clock_timestamp()) / p_window) * p_window
  );
begin
  insert into private.group_call_rate_limits as r (user_id, action, bucket, n)
  values (p_uid, p_action, v_b, 1)
  on conflict (user_id, action) do update set
    n = case when r.bucket = excluded.bucket then r.n + 1 else 1 end,
    bucket = excluded.bucket
  where r.bucket <> excluded.bucket or r.n < p_max;
  if not found then
    raise exception 'call rate limit exceeded' using errcode = 'P0001';
  end if;
end
$$;

create or replace function private.gc_roster(p_call uuid)
returns jsonb
language sql
stable
security definer
set search_path = ''
as $$
  select coalesce(
    jsonb_agg(
      jsonb_build_object(
        'user_id', user_id,
        'sid', session_id,
        'video', with_video,
        'muted', muted,
        'cam', cam_on,
        'sharing', sharing,
        'share_audio', share_audio,
        'joined_at', joined_at
      ) order by joined_at, user_id
    ),
    '[]'::jsonb
  )
  from public.group_call_participants
  where call_id = p_call;
$$;

create or replace function private.gc_reap(p_channel uuid)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_n integer;
begin
  delete from public.group_call_participants p
  where p.channel_id = p_channel
    and (
      p.last_seen < now() - interval '50 seconds'
      or not exists (
        select 1
        from public.channel_members m
        where m.channel_id = p.channel_id
          and m.user_id = p.user_id
      )
    );
  get diagnostics v_n = row_count;
  return v_n > 0;
end
$$;

create or replace function private.gc_broadcast_call(
  p_channel uuid,
  p_call uuid,
  p_active boolean,
  p_video boolean
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  r record;
begin
  for r in
    select user_id
    from public.channel_members
    where channel_id = p_channel
    limit 200
  loop
    perform realtime.send(
      jsonb_build_object(
        'type', 'g-call',
        'channel_id', p_channel,
        'call_id', p_call,
        'active', p_active,
        'video', p_video
      ),
      'call-signal',
      'calls:' || r.user_id::text,
      true
    );
  end loop;
end
$$;

create or replace function private.gc_broadcast_roster(
  p_call uuid,
  p_channel uuid
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  r record;
  v_roster jsonb := private.gc_roster(p_call);
begin
  for r in
    select user_id
    from public.group_call_participants
    where call_id = p_call
  loop
    perform realtime.send(
      jsonb_build_object(
        'type', 'g-roster',
        'channel_id', p_channel,
        'call_id', p_call,
        'participants', v_roster
      ),
      'call-signal',
      'calls:' || r.user_id::text,
      true
    );
  end loop;
end
$$;

create or replace function private.gc_after_change(
  p_channel uuid,
  p_call uuid
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_video boolean;
begin
  if exists (
    select 1
    from public.group_call_participants
    where call_id = p_call
  ) then
    perform private.gc_broadcast_roster(p_call, p_channel);
  else
    update public.group_calls
    set ended_at = now()
    where id = p_call
      and ended_at is null
    returning with_video into v_video;

    if found then
      perform private.gc_broadcast_call(p_channel, p_call, false, v_video);
    end if;
  end if;
end
$$;

create or replace function private.gc_get_group_call_impl(p_channel_id uuid)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  me uuid := (select auth.uid());
  v_call public.group_calls;
  v_roster jsonb;
begin
  if me is null then
    raise exception 'not authenticated' using errcode = '42501';
  end if;

  if p_channel_id is null or not exists (
    select 1
    from public.channels c
    join public.channel_members m
      on m.channel_id = c.id
     and m.user_id = me
    where c.id = p_channel_id
      and c.type = 'group'
  ) then
    raise exception 'call is not allowed' using errcode = '42501';
  end if;

  perform private.gc_consume(me, 'gget', 10, 20);

  select * into v_call
  from public.group_calls
  where channel_id = p_channel_id
    and ended_at is null;

  if not found then
    return jsonb_build_object('active', false);
  end if;

  select coalesce(
    jsonb_agg(
      jsonb_build_object(
        'user_id', user_id,
        'sid', session_id,
        'video', with_video,
        'muted', muted,
        'cam', cam_on,
        'sharing', sharing,
        'share_audio', share_audio,
        'joined_at', joined_at
      ) order by joined_at, user_id
    ),
    '[]'::jsonb
  ) into v_roster
  from public.group_call_participants
  where call_id = v_call.id
    and last_seen > now() - interval '50 seconds';

  if jsonb_array_length(v_roster) = 0 then
    return jsonb_build_object('active', false);
  end if;

  return jsonb_build_object(
    'active', true,
    'call_id', v_call.id,
    'video', v_call.with_video,
    'started_at', v_call.started_at,
    'participants', v_roster
  );
end
$$;

create or replace function private.gc_join_group_call_impl(
  p_channel_id uuid,
  p_video boolean default false
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  me uuid := (select auth.uid());
  v_call uuid;
  v_sid uuid;
  v_cnt integer;
  v_new boolean := false;
  v_video boolean := coalesce(p_video, false);
begin
  if me is null then
    raise exception 'not authenticated' using errcode = '42501';
  end if;
  if p_channel_id is null then
    raise exception 'invalid call request' using errcode = '22023';
  end if;

  perform private.gc_consume(me, 'gjoin10', 10, 4);
  perform private.gc_consume(me, 'gjoin60', 60, 15);

  if not exists (
    select 1
    from public.channels c
    join public.channel_members m
      on m.channel_id = c.id
     and m.user_id = me
    where c.id = p_channel_id
      and c.type = 'group'
  ) then
    raise exception 'call is not allowed' using errcode = '42501';
  end if;

  perform pg_advisory_xact_lock(
    hashtextextended('gcall:' || p_channel_id::text, 0)
  );

  delete from public.group_calls
  where channel_id = p_channel_id
    and ended_at < now() - interval '1 day';

  perform private.gc_reap(p_channel_id);

  select id into v_call
  from public.group_calls
  where channel_id = p_channel_id
    and ended_at is null;

  if v_call is not null and not exists (
    select 1
    from public.group_call_participants
    where call_id = v_call
  ) then
    update public.group_calls
    set ended_at = now()
    where id = v_call;
    v_call := null;
  end if;

  if v_call is null then
    insert into public.group_calls (channel_id, started_by, with_video)
    values (p_channel_id, me, v_video)
    returning id into v_call;
    v_new := true;
  elsif v_video then
    update public.group_calls
    set with_video = true
    where id = v_call
      and not with_video;
  end if;

  select count(*) into v_cnt
  from public.group_call_participants
  where call_id = v_call
    and user_id <> me;

  if v_cnt >= 6 then
    raise exception 'call is full' using errcode = 'P0002';
  end if;

  insert into public.group_call_participants (
    call_id, channel_id, user_id, with_video, cam_on
  )
  values (
    v_call, p_channel_id, me, v_video, v_video
  )
  on conflict (call_id, user_id)
  do update set
    session_id = gen_random_uuid(),
    with_video = excluded.with_video,
    cam_on = excluded.cam_on,
    muted = false,
    sharing = false,
    share_audio = false,
    joined_at = now(),
    last_seen = now()
  returning session_id into v_sid;

  perform private.gc_broadcast_roster(v_call, p_channel_id);

  if v_new then
    perform private.gc_broadcast_call(p_channel_id, v_call, true, v_video);
  elsif v_video then
    perform private.gc_broadcast_call(p_channel_id, v_call, true, true);
  end if;

  return jsonb_build_object(
    'call_id', v_call,
    'session_id', v_sid,
    'participants', private.gc_roster(v_call)
  );
end
$$;

create or replace function private.gc_group_call_state_impl(
  p_channel_id uuid,
  p_session_id uuid,
  p_muted boolean default null,
  p_cam boolean default null,
  p_sharing boolean default null,
  p_share_audio boolean default null
)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  me uuid := (select auth.uid());
  v_call uuid;
  v_old public.group_call_participants;
  v_reaped boolean;
  v_changed boolean;
begin
  if me is null then
    raise exception 'not authenticated' using errcode = '42501';
  end if;
  if p_channel_id is null or p_session_id is null then
    raise exception 'invalid call request' using errcode = '22023';
  end if;

  perform private.gc_consume(me, 'gstate', 10, 30);
  perform pg_advisory_xact_lock(
    hashtextextended('gcall:' || p_channel_id::text, 0)
  );

  select id into v_call
  from public.group_calls
  where channel_id = p_channel_id
    and ended_at is null;

  if v_call is null then
    return false;
  end if;

  v_reaped := private.gc_reap(p_channel_id);

  select * into v_old
  from public.group_call_participants
  where call_id = v_call
    and user_id = me
    and session_id = p_session_id;

  if not found then
    if v_reaped then
      perform private.gc_after_change(p_channel_id, v_call);
    end if;
    return false;
  end if;

  v_changed :=
    (p_muted is not null and p_muted <> v_old.muted)
    or (p_cam is not null and p_cam <> v_old.cam_on)
    or (p_sharing is not null and p_sharing <> v_old.sharing)
    or (p_share_audio is not null and p_share_audio <> v_old.share_audio);

  update public.group_call_participants
  set
    last_seen = now(),
    muted = coalesce(p_muted, muted),
    cam_on = coalesce(p_cam, cam_on),
    sharing = coalesce(p_sharing, sharing),
    share_audio = case
      when coalesce(p_sharing, sharing)
        then coalesce(p_share_audio, share_audio)
      else false
    end
  where call_id = v_call
    and user_id = me
    and session_id = p_session_id;

  if v_changed or v_reaped then
    perform private.gc_after_change(p_channel_id, v_call);
  end if;
  return true;
end
$$;

create or replace function private.gc_leave_group_call_impl(p_channel_id uuid)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  me uuid := (select auth.uid());
  v_call uuid;
begin
  if me is null then
    raise exception 'not authenticated' using errcode = '42501';
  end if;
  if p_channel_id is null then
    raise exception 'invalid call request' using errcode = '22023';
  end if;

  perform private.gc_consume(me, 'gleave', 10, 8);
  perform pg_advisory_xact_lock(
    hashtextextended('gcall:' || p_channel_id::text, 0)
  );

  select id into v_call
  from public.group_calls
  where channel_id = p_channel_id
    and ended_at is null;

  if v_call is null then return; end if;

  delete from public.group_call_participants
  where call_id = v_call
    and user_id = me;

  perform private.gc_reap(p_channel_id);
  perform private.gc_after_change(p_channel_id, v_call);
end
$$;

create or replace function private.gc_send_group_call_signal_impl(
  p_channel_id uuid,
  p_to uuid,
  p_payload jsonb
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  me uuid := (select auth.uid());
  v_type text;
  v_call uuid;
  v_sid uuid;
  v_to_sid uuid;
  v_clean jsonb;
  v_media jsonb;
begin
  if me is null then
    raise exception 'not authenticated' using errcode = '42501';
  end if;

  if p_channel_id is null
     or p_to is null
     or p_to = me
     or p_payload is null
     or jsonb_typeof(p_payload) <> 'object'
     or pg_column_size(p_payload) > 65536 then
    raise exception 'invalid call signal' using errcode = '22023';
  end if;

  v_type := p_payload ->> 'type';
  if v_type is null or v_type not in ('g-offer', 'g-answer', 'g-ice') then
    raise exception 'invalid call signal' using errcode = '22023';
  end if;

  if v_type in ('g-offer', 'g-answer') then
    if jsonb_typeof(p_payload -> 'sdp') <> 'object'
       or p_payload -> 'sdp' ->> 'type' <> substr(v_type, 3)
       or coalesce(p_payload -> 'sdp' ->> 'sdp', '') = ''
       or length(p_payload -> 'sdp' ->> 'sdp') > 60000 then
      raise exception 'invalid call description' using errcode = '22023';
    end if;

    if p_payload ? 'media' then
      if jsonb_typeof(p_payload -> 'media') <> 'object'
         or pg_column_size(p_payload -> 'media') > 1024
         or (p_payload -> 'media' ? 'camera_stream_id' and jsonb_typeof(p_payload -> 'media' -> 'camera_stream_id') <> 'string')
         or (p_payload -> 'media' ? 'screen_stream_id' and jsonb_typeof(p_payload -> 'media' -> 'screen_stream_id') <> 'string')
         or length(coalesce(p_payload -> 'media' ->> 'camera_stream_id', '')) > 200
         or length(coalesce(p_payload -> 'media' ->> 'screen_stream_id', '')) > 200
      then
        raise exception 'invalid media metadata' using errcode = '22023';
      end if;
      v_media := jsonb_build_object(
        'camera_stream_id', nullif(p_payload -> 'media' ->> 'camera_stream_id', ''),
        'screen_stream_id', nullif(p_payload -> 'media' ->> 'screen_stream_id', '')
      );
    else
      v_media := jsonb_build_object(
        'camera_stream_id', null,
        'screen_stream_id', null
      );
    end if;

    perform private.gc_consume(me, 'gneg10', 10, 30);
    perform private.gc_consume(me, 'gneg60', 60, 120);
  else
    if jsonb_typeof(p_payload -> 'candidate') <> 'object'
       or pg_column_size(p_payload -> 'candidate') > 8192
       or length(coalesce(p_payload -> 'candidate' ->> 'candidate', '')) > 4096
       or length(coalesce(p_payload -> 'candidate' ->> 'sdpMid', '')) > 256 then
      raise exception 'invalid call candidate' using errcode = '22023';
    end if;
    perform private.gc_consume(me, 'gice10', 10, 200);
  end if;

  if not exists (
    select 1 from public.channels c
    where c.id = p_channel_id and c.type = 'group'
  )
  or not exists (
    select 1 from public.channel_members
    where channel_id = p_channel_id and user_id = me
  )
  or not exists (
    select 1 from public.channel_members
    where channel_id = p_channel_id and user_id = p_to
  ) then
    raise exception 'call is not allowed' using errcode = '42501';
  end if;

  select g.id into v_call
  from public.group_calls g
  where g.channel_id = p_channel_id
    and g.ended_at is null;

  select session_id into v_sid
  from public.group_call_participants
  where call_id = v_call
    and user_id = me
    and last_seen > now() - interval '60 seconds';

  select session_id into v_to_sid
  from public.group_call_participants
  where call_id = v_call
    and user_id = p_to
    and last_seen > now() - interval '60 seconds';

  if v_call is null or v_sid is null or v_to_sid is null then
    raise exception 'call is not allowed' using errcode = '42501';
  end if;

  v_clean := jsonb_build_object(
    'type', v_type,
    'channel_id', p_channel_id,
    'call_id', v_call,
    'sid', v_sid,
    'to_sid', v_to_sid,
    'from', me::text
  );

  if v_type = 'g-ice' then
    v_clean := v_clean || jsonb_build_object('candidate', p_payload -> 'candidate');
  else
    v_clean := v_clean || jsonb_build_object(
      'sdp', p_payload -> 'sdp',
      'media', v_media
    );
  end if;

  perform realtime.send(
    v_clean,
    'call-signal',
    'calls:' || p_to::text,
    true
  );
end
$$;

-- Private implementation functions are never directly callable by client roles.
revoke all on function private.gc_consume(uuid,text,integer,integer) from public, anon, authenticated;
revoke all on function private.gc_roster(uuid) from public, anon, authenticated;
revoke all on function private.gc_reap(uuid) from public, anon, authenticated;
revoke all on function private.gc_broadcast_call(uuid,uuid,boolean,boolean) from public, anon, authenticated;
revoke all on function private.gc_broadcast_roster(uuid,uuid) from public, anon, authenticated;
revoke all on function private.gc_after_change(uuid,uuid) from public, anon, authenticated;
revoke all on function private.gc_get_group_call_impl(uuid) from public, anon, authenticated;
revoke all on function private.gc_join_group_call_impl(uuid,boolean) from public, anon, authenticated;
revoke all on function private.gc_group_call_state_impl(uuid,uuid,boolean,boolean,boolean,boolean) from public, anon, authenticated;
revoke all on function private.gc_leave_group_call_impl(uuid) from public, anon, authenticated;
revoke all on function private.gc_send_group_call_signal_impl(uuid,uuid,jsonb) from public, anon, authenticated;

-- No client is allowed to write directly to the personal call inbox. Group-call
-- signaling is emitted only by the authenticated RPC above.
drop policy if exists call_inbox_select_own on realtime.messages;
create policy call_inbox_select_own
on realtime.messages
for select to authenticated
using (
  extension = 'broadcast'
  and realtime.topic() ~ '^calls:[0-9a-f-]{36}$'
  and realtime.topic() = 'calls:' || (select auth.uid())::text
);


create or replace function public.get_group_call(p_channel_id uuid)
returns jsonb
language plpgsql
security invoker
set search_path = ''
as $$
begin
  return private.gc_get_group_call_impl(p_channel_id);
end
$$;

create or replace function public.join_group_call(
  p_channel_id uuid,
  p_video boolean default false
)
returns jsonb
language plpgsql
security invoker
set search_path = ''
as $$
begin
  return private.gc_join_group_call_impl(p_channel_id, p_video);
end
$$;

create or replace function public.group_call_state(
  p_channel_id uuid,
  p_session_id uuid,
  p_muted boolean default null,
  p_cam boolean default null,
  p_sharing boolean default null,
  p_share_audio boolean default null
)
returns boolean
language plpgsql
security invoker
set search_path = ''
as $$
begin
  return private.gc_group_call_state_impl(
    p_channel_id,
    p_session_id,
    p_muted,
    p_cam,
    p_sharing,
    p_share_audio
  );
end
$$;

create or replace function public.leave_group_call(p_channel_id uuid)
returns void
language plpgsql
security invoker
set search_path = ''
as $$
begin
  perform private.gc_leave_group_call_impl(p_channel_id);
end
$$;

create or replace function public.send_group_call_signal(
  p_channel_id uuid,
  p_to uuid,
  p_payload jsonb
)
returns void
language plpgsql
security invoker
set search_path = ''
as $$
begin
  perform private.gc_send_group_call_signal_impl(
    p_channel_id,
    p_to,
    p_payload
  );
end
$$;

revoke all on function public.get_group_call(uuid) from public, anon;
revoke all on function public.join_group_call(uuid,boolean) from public, anon;
revoke all on function public.group_call_state(uuid,uuid,boolean,boolean,boolean,boolean) from public, anon;
revoke all on function public.leave_group_call(uuid) from public, anon;
revoke all on function public.send_group_call_signal(uuid,uuid,jsonb) from public, anon;

grant execute on function public.get_group_call(uuid) to authenticated;
grant execute on function public.join_group_call(uuid,boolean) to authenticated;
grant execute on function public.group_call_state(uuid,uuid,boolean,boolean,boolean,boolean) to authenticated;
grant execute on function public.leave_group_call(uuid) to authenticated;
grant execute on function public.send_group_call_signal(uuid,uuid,jsonb) to authenticated;

commit;
