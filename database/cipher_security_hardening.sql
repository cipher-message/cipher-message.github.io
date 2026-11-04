-- DO NOT RUN THIS FILE AS A SINGLE SCRIPT.
-- Production hardening has been applied through separately reviewed migrations
-- in database/*.sql. This historical aggregate draft can contain stale or
-- overlapping changes; use the focused migration files instead.
begin;
create schema if not exists private;
revoke all on schema private from public, anon, authenticated;

-- Keep wrapped private-key material outside the broadly readable profile row.
create table if not exists public.profile_secrets (
  user_id uuid primary key references public.profiles(id) on delete cascade,
  wrapped_private_key text,
  wrap_iv text,
  wrap_salt text,
  updated_at timestamptz not null default now()
);
alter table public.profile_secrets enable row level security;
revoke all on public.profile_secrets from public, anon;
grant select, insert, update on public.profile_secrets to authenticated;
drop policy if exists "profile_secrets_select_self" on public.profile_secrets;
create policy "profile_secrets_select_self" on public.profile_secrets for select to authenticated using (user_id=(select auth.uid()));
drop policy if exists "profile_secrets_insert_self" on public.profile_secrets;
create policy "profile_secrets_insert_self" on public.profile_secrets for insert to authenticated with check (user_id=(select auth.uid()));
drop policy if exists "profile_secrets_update_self" on public.profile_secrets;
create policy "profile_secrets_update_self" on public.profile_secrets for update to authenticated using (user_id=(select auth.uid())) with check (user_id=(select auth.uid()));
insert into public.profile_secrets(user_id,wrapped_private_key,wrap_iv,wrap_salt)
select id,wrapped_private_key,wrap_iv,wrap_salt from public.profiles
where wrapped_private_key is not null or wrap_iv is not null or wrap_salt is not null
on conflict (user_id) do nothing;
revoke select on public.profiles from public,anon,authenticated;
grant select (id,username,display_name,avatar_url,status_message,presence,public_key,created_at) on public.profiles to authenticated;
revoke insert on public.profiles from public,anon,authenticated;
grant insert (id,username,display_name,avatar_url,status_message,presence,public_key,created_at) on public.profiles to authenticated;
revoke update (wrapped_private_key,wrap_iv,wrap_salt) on public.profiles from public,anon,authenticated;
revoke update on public.profiles from public,anon,authenticated;
grant update (username,display_name,avatar_url,status_message,presence,public_key) on public.profiles to authenticated;

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
declare
  v_now timestamptz := clock_timestamp();
  v_short timestamptz;
  v_long timestamptz;
begin
  if p_uid is null or p_action is null or p_short_seconds < 1
     or p_long_seconds < p_short_seconds or p_short_max < 1 or p_long_max < p_short_max then
    raise exception 'invalid rate configuration' using errcode = '22023';
  end if;
  v_short := to_timestamp(floor(extract(epoch from v_now) / p_short_seconds) * p_short_seconds);
  v_long := to_timestamp(floor(extract(epoch from v_now) / p_long_seconds) * p_long_seconds);
  insert into private.action_rate_limits as r
    (user_id,action,short_bucket,short_count,long_bucket,long_count)
  values (p_uid,p_action,v_short,1,v_long,1)
  on conflict (user_id,action) do update set
    short_count = case when r.short_bucket = excluded.short_bucket then r.short_count + 1 else 1 end,
    short_bucket = excluded.short_bucket,
    long_count = case when r.long_bucket = excluded.long_bucket then r.long_count + 1 else 1 end,
    long_bucket = excluded.long_bucket
  where (r.short_bucket <> excluded.short_bucket or r.short_count < p_short_max)
    and (r.long_bucket <> excluded.long_bucket or r.long_count < p_long_max);
  if not found then raise exception 'rate limit exceeded for %',p_action using errcode = 'P0001'; end if;
end;
$$;
revoke all on function private.consume_action_limit(uuid,text,integer,integer,integer,integer) from public,anon,authenticated;

-- Signup has no authenticated user id yet; use a short-lived IP digest from the
-- Edge Function, never the raw address, and grant this RPC only to service_role.
create table if not exists private.signup_ip_rate_limits (
  ip_hash text primary key,
  minute_bucket timestamptz not null,
  minute_count integer not null,
  hour_bucket timestamptz not null,
  hour_count integer not null
);
alter table private.signup_ip_rate_limits enable row level security;
revoke all on private.signup_ip_rate_limits from public,anon,authenticated;
create or replace function public.consume_signup_ip_rate_limit(p_ip_hash text)
returns void language plpgsql security definer set search_path = ''
as $$
declare v_now timestamptz := clock_timestamp(); v_minute timestamptz; v_hour timestamptz;
begin
  if p_ip_hash is null or p_ip_hash !~ '^[0-9a-f]{64}$' then raise exception 'invalid rate key' using errcode='22023'; end if;
  v_minute := to_timestamp(floor(extract(epoch from v_now)/60)*60);
  v_hour := to_timestamp(floor(extract(epoch from v_now)/3600)*3600);
  insert into private.signup_ip_rate_limits as r(ip_hash,minute_bucket,minute_count,hour_bucket,hour_count)
  values(p_ip_hash,v_minute,1,v_hour,1)
  on conflict(ip_hash) do update set
    minute_count=case when r.minute_bucket=excluded.minute_bucket then r.minute_count+1 else 1 end,
    minute_bucket=excluded.minute_bucket,
    hour_count=case when r.hour_bucket=excluded.hour_bucket then r.hour_count+1 else 1 end,
    hour_bucket=excluded.hour_bucket
  where (r.minute_bucket<>excluded.minute_bucket or r.minute_count<5)
    and (r.hour_bucket<>excluded.hour_bucket or r.hour_count<30);
  if not found then raise exception 'signup rate limit exceeded' using errcode='P0001'; end if;
end;
$$;
revoke all on function public.consume_signup_ip_rate_limit(text) from public,anon,authenticated;
grant execute on function public.consume_signup_ip_rate_limit(text) to service_role;

create or replace function private.guard_cipher_insert()
returns trigger language plpgsql security definer set search_path = ''
as $$
declare v_uid uuid := (select auth.uid()); v_now timestamptz := clock_timestamp(); v_channel_type text; v_member_count integer;
begin
  if v_uid is not null then
    case tg_table_name
      when 'messages' then perform private.consume_action_limit(v_uid,'messages',10,8,60,40);
      when 'attachments' then perform private.consume_action_limit(v_uid,'attachments',10,4,60,24);
      when 'channels' then perform private.consume_action_limit(v_uid,'channels',600,5,86400,20);
      when 'channel_members' then
        if new.user_id=v_uid then perform private.consume_action_limit(v_uid,'channel_joins',600,10,86400,40);
        else perform private.consume_action_limit(v_uid,'channel_invites',600,10,86400,100); end if;
      when 'friend_requests' then perform private.consume_action_limit(v_uid,'friend_requests',600,3,86400,15);
      when 'reports' then perform private.consume_action_limit(v_uid,'reports',3600,2,86400,5);
      when 'reactions' then perform private.consume_action_limit(v_uid,'reactions',10,12,60,60);
      when 'message_reactions' then perform private.consume_action_limit(v_uid,'reactions',10,12,60,60);
      when 'statuses' then perform private.consume_action_limit(v_uid,'statuses',600,3,86400,8);
      when 'status_views' then perform private.consume_action_limit(v_uid,'status_views',60,30,86400,500);
      when 'focus_sessions' then perform private.consume_action_limit(v_uid,'focus_sessions',600,3,86400,20);
      when 'focus_participants' then perform private.consume_action_limit(v_uid,'focus_joins',60,15,86400,200);
    end case;
  end if;
  if tg_table_name = 'profiles' then
    if new.username is null or new.username !~ '^[a-z0-9_]{3,24}$' or new.display_name is null or octet_length(new.display_name)>256 then raise exception 'invalid profile fields' using errcode='22023'; end if;
    new.created_at:=v_now;
  elsif tg_table_name = 'channels' then
    if new.type not in ('dm','group') or (new.type='group' and (new.name is null or length(new.name)<1 or octet_length(new.name)>128)) or coalesce(octet_length(new.topic),0)>1000 then raise exception 'invalid channel details' using errcode='22023'; end if;
    if new.type='dm' then new.is_public:=false; end if;
    new.created_at:=v_now;
  elsif tg_table_name = 'channel_members' then
    if new.role not in ('owner','member') then raise exception 'invalid membership role' using errcode='22023'; end if;
    select c.type into v_channel_type from public.channels c where c.id=new.channel_id for update;
    if v_channel_type='dm' then
      select count(*) into v_member_count from public.channel_members cm where cm.channel_id=new.channel_id;
      if v_member_count>=2 then raise exception 'direct messages can have only two members' using errcode='42501'; end if;
    end if;
    new.joined_at:=v_now; new.last_read_at:=v_now; new.muted:=false; new.pinned:=false; new.archived:=false; new.background:=null;
  elsif tg_table_name = 'focus_sessions' then
    if new.duration_seconds is null or new.duration_seconds<300 or new.duration_seconds>7200 or coalesce(octet_length(new.label),0)>128 then raise exception 'invalid focus session settings' using errcode='22023'; end if;
    new.started_at:=v_now; new.created_at:=v_now; new.ends_at:=v_now + make_interval(secs=>new.duration_seconds); new.ended_early:=false;
  elsif tg_table_name = 'focus_participants' then
    new.joined_at:=v_now; new.left_at:=null; new.focused_seconds:=null;
  elsif tg_table_name = 'messages' then
    if new.content is not null and octet_length(new.content) > 16384 then raise exception 'message too large' using errcode='22001'; end if;
    if new.ciphertext is not null and octet_length(new.ciphertext) > 65536 then raise exception 'encrypted message too large' using errcode='22001'; end if;
    if new.iv is not null and octet_length(new.iv) > 256 then raise exception 'invalid encryption metadata' using errcode='22023'; end if;
    if new.encrypted_keys is not null and (jsonb_typeof(new.encrypted_keys) <> 'object' or pg_column_size(new.encrypted_keys) > 32768) then raise exception 'invalid encryption metadata' using errcode='22023'; end if;
    new.created_at := v_now; new.edited_at := null; new.deleted := false; new.pinned := false; new.expires_at := null;
    if new.reply_to is not null and not exists(select 1 from public.messages m where m.id=new.reply_to and m.channel_id=new.channel_id) then
      raise exception 'reply target unavailable' using errcode='23503';
    end if;
  elsif tg_table_name = 'attachments' then
    if new.filename is null or length(new.filename)>255 or new.size is null or new.size<0 or new.size>26214400 then raise exception 'attachment exceeds 25 MiB or has invalid metadata' using errcode='22023'; end if;
    new.created_at := v_now;
  elsif tg_table_name = 'friend_requests' then
    if new.receiver_id = new.sender_id then raise exception 'cannot request yourself' using errcode='22023'; end if;
    new.status := 'pending'; new.created_at := v_now; new.responded_at := null;
  elsif tg_table_name = 'reports' then
    if new.reported_id is null or new.reported_id=new.reporter_id or new.reason is null or length(new.reason)<1 or length(new.reason)>1000 then raise exception 'invalid report details' using errcode='22023'; end if;
    new.created_at := v_now;
  elsif tg_table_name in ('reactions','message_reactions') then
    if new.emoji is null or length(new.emoji)<1 or octet_length(new.emoji)>64 then raise exception 'invalid reaction' using errcode='22023'; end if;
    new.created_at := v_now;
  elsif tg_table_name = 'statuses' then
    if new.type='text' and (new.text_content is null or octet_length(new.text_content)>2000) then raise exception 'invalid status text' using errcode='22023'; end if;
    if new.bg_color is not null and new.bg_color !~ '^#[0-9a-fA-F]{6}$' then raise exception 'invalid status color' using errcode='22023'; end if;
    if new.type='image' and (new.storage_path is null or split_part(new.storage_path,'/',1)<>'status' or split_part(new.storage_path,'/',2)<>new.user_id::text) then raise exception 'invalid status media path' using errcode='22023'; end if;
    new.created_at := v_now; new.expires_at := v_now + interval '24 hours';
  elsif tg_table_name = 'status_views' then new.viewed_at := v_now;
  end if;
  return new;
end;
$$;

create or replace function private.guard_cipher_update()
returns trigger language plpgsql security definer set search_path = ''
as $$
declare v_now timestamptz := clock_timestamp();
begin
  case tg_table_name
    when 'profiles' then
      if new.id is distinct from old.id or new.created_at is distinct from old.created_at then raise exception 'profile identity immutable' using errcode='42501'; end if;
      if new.username is distinct from old.username and (new.username is null or new.username !~ '^[a-z0-9_]{3,24}$') then raise exception 'invalid username' using errcode='22023'; end if;
      if new.display_name is distinct from old.display_name and (new.display_name is null or octet_length(new.display_name)>256) then raise exception 'invalid display name' using errcode='22023'; end if;
      if new.status_message is distinct from old.status_message and coalesce(octet_length(new.status_message),0)>1000 then raise exception 'status message too large' using errcode='22023'; end if;
      if new.public_key is distinct from old.public_key and new.public_key is not null and (jsonb_typeof(new.public_key)<>'object' or pg_column_size(new.public_key)>4096) then raise exception 'invalid public key' using errcode='22023'; end if;
      if new.avatar_url is distinct from old.avatar_url and new.avatar_url is not null and new.avatar_url !~ ('^https://cvnbsgfruntizatfmhah[.]supabase[.]co/storage/v1/object/public/avatars/'||new.id::text||'/') then raise exception 'invalid avatar URL' using errcode='22023'; end if;
    when 'channels' then
      if new.id is distinct from old.id or new.type is distinct from old.type or new.created_at is distinct from old.created_at
         or (new.created_by is distinct from old.created_by and not (new.created_by is null and old.created_by=(select auth.uid()))) then raise exception 'channel identity immutable' using errcode='42501'; end if;
      if (new.name is distinct from old.name or new.topic is distinct from old.topic or new.is_public is distinct from old.is_public or new.disappear_seconds is distinct from old.disappear_seconds or new.disappearing_seconds is distinct from old.disappearing_seconds or new.ultra_private is distinct from old.ultra_private)
         and not exists(select 1 from public.channel_members cm where cm.channel_id=new.id and cm.user_id=(select auth.uid()) and cm.role='owner') then raise exception 'channel owner permission required' using errcode='42501'; end if;
      if coalesce(octet_length(new.name),0)>128 or coalesce(octet_length(new.topic),0)>1000 or (new.disappear_seconds is not null and new.disappear_seconds not in (86400,604800,7776000)) then raise exception 'invalid channel settings' using errcode='22023'; end if;
      if new.background is distinct from old.background and new.background is not null then
        if pg_column_size(new.background)>8192 then raise exception 'background settings too large' using errcode='22001'; end if;
        if jsonb_typeof(new.background)<>'object' then raise exception 'invalid background settings' using errcode='22023'; end if;
        if new.background->>'type'='preset' and new.background->>'id' not in ('basketball','soccer','love','ocean','forest','space','sunset','confetti','mint') then raise exception 'invalid background preset' using errcode='22023'; end if;
        if new.background->>'type'='image' and left(new.background->>'path',length((select auth.uid())::text||'/'||new.id::text||'-'))<>(select auth.uid())::text||'/'||new.id::text||'-' then raise exception 'invalid background path' using errcode='42501'; end if;
        if new.background->>'type' not in ('none','preset','image') then raise exception 'invalid background type' using errcode='22023'; end if;
      end if;
    when 'channel_members' then
      if new.channel_id is distinct from old.channel_id or new.user_id is distinct from old.user_id or new.role is distinct from old.role or new.joined_at is distinct from old.joined_at then raise exception 'membership identity and role immutable' using errcode='42501'; end if;
      if new.last_read_at > v_now then new.last_read_at := v_now; end if;
      if new.background is not null and pg_column_size(new.background)>16384 then raise exception 'member settings too large' using errcode='22001'; end if;
    when 'messages' then
      if new.id is distinct from old.id or new.channel_id is distinct from old.channel_id or new.created_at is distinct from old.created_at or new.expires_at is distinct from old.expires_at or new.forwarded is distinct from old.forwarded
         or (new.sender_id is distinct from old.sender_id and not (new.sender_id is null and old.sender_id=(select auth.uid()))) then raise exception 'message identity immutable' using errcode='42501'; end if;
      if new.content is not null and octet_length(new.content)>16384 then raise exception 'message too large' using errcode='22001'; end if;
      if new.ciphertext is not null and octet_length(new.ciphertext)>65536 then raise exception 'encrypted message too large' using errcode='22001'; end if;
      if new.encrypted_keys is not null and (jsonb_typeof(new.encrypted_keys)<>'object' or pg_column_size(new.encrypted_keys)>32768) then raise exception 'invalid encryption metadata' using errcode='22023'; end if;
      new.edited_at := case when new.content is distinct from old.content or new.ciphertext is distinct from old.ciphertext or new.iv is distinct from old.iv or new.encrypted_keys is distinct from old.encrypted_keys then v_now else old.edited_at end;
    when 'friend_requests' then
      if new.id is distinct from old.id or new.sender_id is distinct from old.sender_id or new.receiver_id is distinct from old.receiver_id or new.created_at is distinct from old.created_at or old.status<>'pending' or new.status<>'accepted' then raise exception 'invalid friend request transition' using errcode='42501'; end if;
      new.responded_at := v_now;
    when 'focus_sessions' then
      if new.id is distinct from old.id or new.channel_id is distinct from old.channel_id or new.started_by is distinct from old.started_by or new.duration_seconds is distinct from old.duration_seconds or new.started_at is distinct from old.started_at or new.ends_at is distinct from old.ends_at or new.created_at is distinct from old.created_at or new.label is distinct from old.label or old.ended_early or not new.ended_early then raise exception 'invalid focus session transition' using errcode='42501'; end if;
    when 'focus_participants' then
      if new.session_id is distinct from old.session_id or new.user_id is distinct from old.user_id then raise exception 'participant identity immutable' using errcode='42501'; end if;
      if old.left_at is null and new.left_at is not null then new.joined_at:=old.joined_at; new.left_at:=v_now; new.focused_seconds:=greatest(0,floor(extract(epoch from v_now-old.joined_at))::integer);
      elsif old.left_at is not null and new.left_at is null then new.joined_at:=v_now; new.focused_seconds:=null;
      elsif new.joined_at is distinct from old.joined_at or new.left_at is distinct from old.left_at or new.focused_seconds is distinct from old.focused_seconds then raise exception 'invalid focus participant transition' using errcode='42501';
      end if;
  end case;
  return new;
end;
$$;
revoke all on function private.guard_cipher_insert() from public,anon,authenticated;
revoke all on function private.guard_cipher_update() from public,anon,authenticated;

drop trigger if exists cipher_guard_messages_insert on public.messages;
create trigger cipher_guard_messages_insert before insert on public.messages for each row execute function private.guard_cipher_insert();
drop trigger if exists cipher_guard_messages_update on public.messages;
create trigger cipher_guard_messages_update before update on public.messages for each row execute function private.guard_cipher_update();
drop trigger if exists cipher_guard_profiles_update on public.profiles;
create trigger cipher_guard_profiles_update before update on public.profiles for each row execute function private.guard_cipher_update();
drop trigger if exists cipher_guard_profiles_insert on public.profiles;
create trigger cipher_guard_profiles_insert before insert on public.profiles for each row execute function private.guard_cipher_insert();
drop trigger if exists cipher_guard_channels_update on public.channels;
create trigger cipher_guard_channels_update before update on public.channels for each row execute function private.guard_cipher_update();
drop trigger if exists cipher_guard_members_update on public.channel_members;
create trigger cipher_guard_members_update before update on public.channel_members for each row execute function private.guard_cipher_update();
drop trigger if exists cipher_guard_friend_requests_insert on public.friend_requests;
create trigger cipher_guard_friend_requests_insert before insert on public.friend_requests for each row execute function private.guard_cipher_insert();
drop trigger if exists cipher_guard_friend_requests_update on public.friend_requests;
create trigger cipher_guard_friend_requests_update before update on public.friend_requests for each row execute function private.guard_cipher_update();
drop trigger if exists cipher_guard_reports_insert on public.reports;
create trigger cipher_guard_reports_insert before insert on public.reports for each row execute function private.guard_cipher_insert();
drop trigger if exists cipher_guard_reactions_insert on public.reactions;
create trigger cipher_guard_reactions_insert before insert on public.reactions for each row execute function private.guard_cipher_insert();
drop trigger if exists cipher_guard_message_reactions_insert on public.message_reactions;
create trigger cipher_guard_message_reactions_insert before insert on public.message_reactions for each row execute function private.guard_cipher_insert();
drop trigger if exists cipher_guard_statuses_insert on public.statuses;
create trigger cipher_guard_statuses_insert before insert on public.statuses for each row execute function private.guard_cipher_insert();
drop trigger if exists cipher_guard_status_views_insert on public.status_views;
create trigger cipher_guard_status_views_insert before insert on public.status_views for each row execute function private.guard_cipher_insert();
drop trigger if exists cipher_guard_attachments_insert on public.attachments;
create trigger cipher_guard_attachments_insert before insert on public.attachments for each row execute function private.guard_cipher_insert();
drop trigger if exists cipher_guard_channels_insert on public.channels;
create trigger cipher_guard_channels_insert before insert on public.channels for each row execute function private.guard_cipher_insert();
drop trigger if exists cipher_guard_members_insert on public.channel_members;
create trigger cipher_guard_members_insert before insert on public.channel_members for each row execute function private.guard_cipher_insert();
drop trigger if exists cipher_guard_focus_sessions_insert on public.focus_sessions;
create trigger cipher_guard_focus_sessions_insert before insert on public.focus_sessions for each row execute function private.guard_cipher_insert();
drop trigger if exists cipher_guard_focus_participants_insert on public.focus_participants;
create trigger cipher_guard_focus_participants_insert before insert on public.focus_participants for each row execute function private.guard_cipher_insert();

drop policy if exists "members_insert" on public.channel_members;
create policy "members_insert" on public.channel_members for insert to authenticated with check (
  (user_id=(select auth.uid()) and role='member' and exists(select 1 from public.channels c where c.id=channel_id and c.type='group' and c.is_public=true))
  or exists(select 1 from public.channels c where c.id=channel_id and c.created_by=(select auth.uid()) and ((user_id=(select auth.uid()) and role='owner') or (user_id<>(select auth.uid()) and role='member')))
);
drop policy if exists "members_update_self" on public.channel_members;
create policy "members_update_self" on public.channel_members for update to authenticated using (user_id=(select auth.uid()) and is_channel_member(channel_id)) with check (user_id=(select auth.uid()) and is_channel_member(channel_id));
drop policy if exists "channels_update" on public.channels;
create policy "channels_update" on public.channels for update to authenticated using (is_channel_member(id)) with check (is_channel_member(id));
drop policy if exists "messages_update" on public.messages;
create policy "messages_update" on public.messages for update to authenticated using (sender_id=(select auth.uid()) and is_channel_member(channel_id)) with check (sender_id=(select auth.uid()) and is_channel_member(channel_id));
drop policy if exists "friend_requests_update" on public.friend_requests;
create policy "friend_requests_update" on public.friend_requests for update to authenticated using (receiver_id=(select auth.uid()) and status='pending') with check (receiver_id=(select auth.uid()) and status='accepted');
drop policy if exists "focus_sessions_update" on public.focus_sessions;
create policy "focus_sessions_update" on public.focus_sessions for update to authenticated using (started_by=(select auth.uid()) and is_channel_member(channel_id)) with check (started_by=(select auth.uid()) and is_channel_member(channel_id));
drop policy if exists "focus_participants_update" on public.focus_participants;
create policy "focus_participants_update" on public.focus_participants for update to authenticated using (user_id=(select auth.uid())) with check (user_id=(select auth.uid()) and exists(select 1 from public.focus_sessions fs where fs.id=session_id and is_channel_member(fs.channel_id)));
drop policy if exists "profiles_select_all" on public.profiles;
create policy "profiles_select_all" on public.profiles for select to authenticated using (true);
drop policy if exists "profiles_update_self" on public.profiles;
create policy "profiles_update_self" on public.profiles for update to authenticated using (id=(select auth.uid())) with check (id=(select auth.uid()));

create or replace function public.set_my_encryption_key(p_public_key jsonb,p_wrapped_private_key text,p_wrap_iv text,p_wrap_salt text)
returns void language plpgsql security invoker set search_path = ''
as $$
declare v_uid uuid := (select auth.uid());
begin
  if v_uid is null then raise exception 'not authenticated' using errcode='42501'; end if;
  if jsonb_typeof(p_public_key)<>'object' or pg_column_size(p_public_key)>4096
     or p_wrapped_private_key is null or length(p_wrapped_private_key)>4096
     or p_wrap_iv is null or length(p_wrap_iv)>128
     or p_wrap_salt is null or length(p_wrap_salt)>128 then
    raise exception 'invalid encryption key metadata' using errcode='22023';
  end if;
  update public.profiles set public_key=p_public_key where id=v_uid;
  if not found then raise exception 'profile unavailable' using errcode='42501'; end if;
  insert into public.profile_secrets(user_id,wrapped_private_key,wrap_iv,wrap_salt,updated_at)
  values(v_uid,p_wrapped_private_key,p_wrap_iv,p_wrap_salt,clock_timestamp())
  on conflict(user_id) do update set wrapped_private_key=excluded.wrapped_private_key,wrap_iv=excluded.wrap_iv,wrap_salt=excluded.wrap_salt,updated_at=excluded.updated_at;
end;
$$;
revoke all on function public.set_my_encryption_key(jsonb,text,text,text) from public,anon;
grant execute on function public.set_my_encryption_key(jsonb,text,text,text) to authenticated;
drop policy if exists "pins_insert" on public.pins;
create policy "pins_insert" on public.pins for insert to authenticated with check (pinned_by=(select auth.uid()) and is_channel_member(channel_id) and exists(select 1 from public.messages m where m.id=pins.message_id and m.channel_id=pins.channel_id));
drop policy if exists "blocks_insert" on public.blocks;
create policy "blocks_insert" on public.blocks for insert to authenticated with check (blocker_id=(select auth.uid()) and blocked_id<>(select auth.uid()));
drop policy if exists "reports_insert" on public.reports;
create policy "reports_insert" on public.reports for insert to authenticated with check (reporter_id=(select auth.uid()) and reported_id is not null and reported_id<>(select auth.uid()));
drop policy if exists "select visible statuses" on public.statuses;
create policy "select visible statuses" on public.statuses for select to authenticated using (
  expires_at>now() and (user_id=(select auth.uid()) or (
    exists(select 1 from public.channel_members mine join public.channel_members them on them.channel_id=mine.channel_id join public.channels c on c.id=mine.channel_id where mine.user_id=(select auth.uid()) and them.user_id=statuses.user_id and c.type='dm')
    and not exists(select 1 from public.blocks b where (b.blocker_id=(select auth.uid()) and b.blocked_id=statuses.user_id) or (b.blocker_id=statuses.user_id and b.blocked_id=(select auth.uid())))
  ))
);
drop policy if exists "insert own statuses" on public.statuses;
create policy "insert own statuses" on public.statuses for insert to authenticated with check (user_id=(select auth.uid()));
drop policy if exists "delete own statuses" on public.statuses;
create policy "delete own statuses" on public.statuses for delete to authenticated using (user_id=(select auth.uid()));
drop policy if exists "insert own views" on public.status_views;
create policy "insert own views" on public.status_views for insert to authenticated with check (
  viewer_id=(select auth.uid()) and exists(select 1 from public.statuses s where s.id=status_id and s.user_id<>(select auth.uid()) and s.expires_at>now())
);
drop policy if exists "select relevant views" on public.status_views;
create policy "select relevant views" on public.status_views for select to authenticated using (
  viewer_id=(select auth.uid()) or exists(select 1 from public.statuses s where s.id=status_id and s.user_id=(select auth.uid()))
);
drop policy if exists "select own hides" on public.message_hides;
create policy "select own hides" on public.message_hides for select to authenticated using (user_id=(select auth.uid()));
drop policy if exists "insert own hides" on public.message_hides;
create policy "insert own hides" on public.message_hides for insert to authenticated with check (user_id=(select auth.uid()) and exists(select 1 from public.messages m where m.id=message_id and is_channel_member(m.channel_id)));
drop policy if exists "delete own hides" on public.message_hides;
create policy "delete own hides" on public.message_hides for delete to authenticated using (user_id=(select auth.uid()));
drop policy if exists "message_reactions_select" on public.message_reactions;
create policy "message_reactions_select" on public.message_reactions for select to authenticated using (exists(select 1 from public.messages m where m.id=message_id and is_channel_member(m.channel_id)));
drop policy if exists "message_reactions_insert" on public.message_reactions;
create policy "message_reactions_insert" on public.message_reactions for insert to authenticated with check (user_id=(select auth.uid()) and exists(select 1 from public.messages m where m.id=message_id and is_channel_member(m.channel_id)));
drop policy if exists "message_reactions_delete" on public.message_reactions;
create policy "message_reactions_delete" on public.message_reactions for delete to authenticated using (user_id=(select auth.uid()));
drop policy if exists "message_stars_select" on public.message_stars;
create policy "message_stars_select" on public.message_stars for select to authenticated using (user_id=(select auth.uid()));
drop policy if exists "message_stars_insert" on public.message_stars;
create policy "message_stars_insert" on public.message_stars for insert to authenticated with check (user_id=(select auth.uid()) and exists(select 1 from public.messages m where m.id=message_id and is_channel_member(m.channel_id)));
drop policy if exists "message_stars_delete" on public.message_stars;
create policy "message_stars_delete" on public.message_stars for delete to authenticated using (user_id=(select auth.uid()));

drop policy if exists "attachments_storage_read" on storage.objects;
create policy "attachments_storage_read" on storage.objects for select to authenticated using (
  bucket_id='attachments' and (
    exists(select 1 from public.messages m where m.channel_id::text=split_part(name,'/',1) and m.id::text=split_part(name,'/',2) and is_channel_member(m.channel_id))
    or exists(select 1 from public.statuses s where s.storage_path=name and s.expires_at>now() and (
      s.user_id=(select auth.uid()) or exists(select 1 from public.channel_members mine join public.channel_members them on them.channel_id=mine.channel_id join public.channels c on c.id=mine.channel_id where mine.user_id=(select auth.uid()) and them.user_id=s.user_id and c.type='dm')
    ) and not exists(select 1 from public.blocks b where (b.blocker_id=(select auth.uid()) and b.blocked_id=s.user_id) or (b.blocker_id=s.user_id and b.blocked_id=(select auth.uid()))))
  )
);
drop policy if exists "attachments_storage_write" on storage.objects;
create policy "attachments_storage_write" on storage.objects for insert to authenticated with check (
  bucket_id='attachments' and (
    exists(select 1 from public.messages m where m.channel_id::text=split_part(name,'/',1) and m.id::text=split_part(name,'/',2) and m.sender_id=(select auth.uid()) and is_channel_member(m.channel_id))
    or (split_part(name,'/',1)='status' and split_part(name,'/',2)=(select auth.uid())::text)
  )
);
drop policy if exists "avatars_update_own" on storage.objects;
create policy "avatars_update_own" on storage.objects for update to authenticated
using (bucket_id='avatars' and (storage.foldername(name))[1]=(select auth.uid())::text)
with check (bucket_id='avatars' and (storage.foldername(name))[1]=(select auth.uid())::text);
drop policy if exists "chatbg_update_own" on storage.objects;
create policy "chatbg_update_own" on storage.objects for update to authenticated
using (bucket_id='chat-backgrounds' and (storage.foldername(name))[1]=(select auth.uid())::text)
with check (bucket_id='chat-backgrounds' and (storage.foldername(name))[1]=(select auth.uid())::text);
drop policy if exists "chatbg_select_own" on storage.objects;
create policy "chatbg_select_own" on storage.objects for select to authenticated using (
  bucket_id='chat-backgrounds' and (
    split_part(name,'/',1)=(select auth.uid())::text
    or exists(select 1 from public.channels c where c.background->>'path'=name and is_channel_member(c.id))
  )
);
-- All writes to the personal call inbox go through send_call_signal(). This
-- prevents a browser from bypassing its authorization and identity checks.
drop policy if exists "call_send_broadcast" on realtime.messages;
drop policy if exists "typing_read_members" on realtime.messages;
create policy "typing_read_members" on realtime.messages for select to authenticated using (
  extension='broadcast' and split_part(realtime.topic(),':',1)='typing' and exists(
    select 1 from public.channel_members cm where cm.channel_id::text=split_part(realtime.topic(),':',2) and cm.user_id=(select auth.uid())
  )
);
drop policy if exists "typing_send_members" on realtime.messages;
create policy "typing_send_members" on realtime.messages for insert to authenticated with check (
  extension='broadcast' and split_part(realtime.topic(),':',1)='typing' and exists(
    select 1 from public.channel_members cm where cm.channel_id::text=split_part(realtime.topic(),':',2) and cm.user_id=(select auth.uid())
  )
);
drop policy if exists "presence_global_read" on realtime.messages;
create policy "presence_global_read" on realtime.messages for select to authenticated using (
  extension='presence' and realtime.topic()='presence:global'
);
drop policy if exists "presence_global_write" on realtime.messages;
create policy "presence_global_write" on realtime.messages for insert to authenticated with check (
  extension='presence' and realtime.topic()='presence:global'
);
update storage.buckets set file_size_limit=26214400 where id='attachments';
update storage.buckets set file_size_limit=5242880, allowed_mime_types=array['image/jpeg','image/png','image/webp','image/gif'] where id='avatars';
update storage.buckets set file_size_limit=10485760, allowed_mime_types=array['image/jpeg','image/png','image/webp','image/gif'] where id='chat-backgrounds';

-- Cover the unindexed foreign keys reported by the current performance advisor.
create index if not exists blocks_blocked_id_idx on public.blocks(blocked_id);
create index if not exists bookmarks_message_id_idx on public.bookmarks(message_id);
create index if not exists channel_members_user_id_idx on public.channel_members(user_id);
create index if not exists channels_created_by_idx on public.channels(created_by);
create index if not exists focus_participants_user_id_idx on public.focus_participants(user_id);
create index if not exists focus_sessions_started_by_idx on public.focus_sessions(started_by);
create index if not exists friend_requests_receiver_id_idx on public.friend_requests(receiver_id);
create index if not exists message_hides_message_id_idx on public.message_hides(message_id);
create index if not exists pins_pinned_by_idx on public.pins(pinned_by);
create index if not exists reactions_user_id_idx on public.reactions(user_id);
create index if not exists reports_reporter_id_idx on public.reports(reporter_id);
create index if not exists status_views_status_id_idx on public.status_views(status_id);

-- The existing schedule authenticates with the public anon key. Pause it until
-- a private service-role credential is configured for the scheduler.
do $$ declare v_job_id bigint; begin
  select jobid into v_job_id from cron.job where jobname='cleanup-old-attachments-daily' limit 1;
  if v_job_id is not null then perform cron.unschedule(v_job_id); end if;
end $$;

create or replace function public.is_channel_member(cid uuid)
returns boolean language sql stable security definer set search_path = ''
as $$ select exists(select 1 from public.channel_members cm where cm.channel_id=cid and cm.user_id=(select auth.uid())); $$;

create or replace function public.set_message_expiry()
returns trigger language plpgsql security invoker set search_path = ''
as $$
declare secs integer;
begin
  select c.disappear_seconds into secs from public.channels c where c.id=new.channel_id;
  if secs is not null and secs>0 then new.expires_at:=clock_timestamp()+make_interval(secs=>secs); end if;
  return new;
end;
$$;

create or replace function public.enforce_allowed_email_domains()
returns trigger language plpgsql security invoker set search_path = ''
as $$
begin
  if new.email is null or lower(split_part(new.email,'@',2)) not in ('yahoo.com','gmail.com','icloud.com','schools.sa.edu.au') then
    raise exception 'Email domain not allowed.';
  end if;
  return new;
end;
$$;

create or replace function public.delete_own_account()
returns void language plpgsql security definer set search_path = ''
as $$
declare uid uuid := (select auth.uid());
begin
  if uid is null then raise exception 'not authenticated' using errcode='42501'; end if;
  update public.messages set sender_id=null where sender_id=uid;
  update public.channels set created_by=null where created_by=uid;
  update public.pins set pinned_by=null where pinned_by=uid;
  update public.reports set reporter_id=null where reporter_id=uid;
  delete from auth.users where id=uid;
end;
$$;

create or replace function public.purge_expired_statuses()
returns void language sql security definer set search_path = ''
as $$ delete from public.statuses where expires_at<clock_timestamp(); $$;
create or replace function public.purge_expired_messages()
returns void language sql security definer set search_path = ''
as $$ update public.messages set deleted=true,content='',ciphertext=null,iv=null,encrypted_keys=null where expires_at is not null and expires_at<clock_timestamp() and deleted=false; $$;

revoke all on function public.purge_expired_statuses() from public,anon,authenticated;
grant execute on function public.purge_expired_statuses() to service_role;
revoke all on function public.purge_expired_messages() from public,anon,authenticated;
revoke all on function public.rls_auto_enable() from public,anon,authenticated;
revoke all on function public.set_message_expiry() from public,anon,authenticated;
revoke all on function public.enforce_allowed_email_domains() from public,anon,authenticated;
revoke all on function public.delete_own_account() from public,anon;
grant execute on function public.delete_own_account() to authenticated;
revoke all on function public.is_channel_member(uuid) from public,anon;
grant execute on function public.is_channel_member(uuid) to authenticated,service_role;

create or replace function public.send_call_signal(peer_id uuid,payload jsonb)
returns void language plpgsql security definer set search_path = ''
as $$
declare
  me uuid := (select auth.uid()); signal_type text; clean_payload jsonb;
  profile_name text; profile_avatar text; dm_channel uuid;
begin
  if me is null then raise exception 'not authenticated' using errcode='42501'; end if;
  if peer_id is null or peer_id=me or payload is null or jsonb_typeof(payload)<>'object' or pg_column_size(payload)>32768 then raise exception 'invalid call signal' using errcode='22023'; end if;
  signal_type:=payload->>'type';
  if signal_type is null or signal_type not in ('offer','answer','ice','hangup','reject') then raise exception 'invalid call signal' using errcode='22023'; end if;
  if signal_type in ('offer','answer') and (payload->>'sdp' is null or jsonb_typeof(payload->'sdp')<>'string' or length(payload->>'sdp')>20000) then raise exception 'invalid call description' using errcode='22023'; end if;
  if signal_type='ice' and (length(coalesce(payload->>'candidate',''))>4096 or length(coalesce(payload->>'sdpMid',''))>256) then raise exception 'invalid call candidate' using errcode='22023'; end if;
  if signal_type='offer' and payload ? 'video' and jsonb_typeof(payload->'video')<>'boolean' then raise exception 'invalid call options' using errcode='22023'; end if;
  select c.id into dm_channel from public.channels c
  join public.channel_members a on a.channel_id=c.id and a.user_id=me
  join public.channel_members b on b.channel_id=c.id and b.user_id=peer_id
  where c.type='dm' and (signal_type<>'offer' or c.id::text=payload->>'dmChannelId')
  order by c.created_at desc limit 1;
  if dm_channel is null or exists(select 1 from public.blocks x where (x.blocker_id=me and x.blocked_id=peer_id) or (x.blocker_id=peer_id and x.blocked_id=me)) then
    raise exception 'call is not allowed' using errcode='42501';
  end if;
  perform private.consume_action_limit(me,'calls:'||peer_id::text,10,3,60,15);
  select p.display_name,p.avatar_url into profile_name,profile_avatar from public.profiles p where p.id=me;
  if signal_type='offer' then clean_payload:=jsonb_build_object('type','offer','sdp',payload->'sdp','video',coalesce((payload->>'video')::boolean,false),'dmChannelId',dm_channel);
  elsif signal_type='answer' then clean_payload:=jsonb_build_object('type','answer','sdp',payload->'sdp');
  elsif signal_type='ice' then clean_payload:=jsonb_build_object('type','ice','candidate',payload->'candidate','sdpMid',payload->'sdpMid','sdpMLineIndex',payload->'sdpMLineIndex');
  else clean_payload:=jsonb_build_object('type',signal_type,'reason',left(coalesce(payload->>'reason',''),64));
  end if;
  perform realtime.send(clean_payload||jsonb_build_object('from',me::text,'fromName',profile_name,'fromAvatar',profile_avatar),'call-signal','calls:'||peer_id::text,true);
end;
$$;
revoke all on function public.send_call_signal(uuid,jsonb) from public,anon;
grant execute on function public.send_call_signal(uuid,jsonb) to authenticated;

create or replace function public.consume_cipher_ai_rate_limit()
returns void language plpgsql security definer set search_path = ''
as $$
begin
  if (select auth.uid()) is null then raise exception 'not authenticated' using errcode='42501'; end if;
  perform private.consume_action_limit((select auth.uid()),'cipher_ai',60,6,86400,40);
end;
$$;
revoke all on function public.consume_cipher_ai_rate_limit() from public,anon;
grant execute on function public.consume_cipher_ai_rate_limit() to authenticated;
commit;
