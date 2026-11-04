-- A request can only be accepted by its recipient; endpoints cannot be
-- rewritten, and server-side limits cap request floods.
begin;

create or replace function private.guard_friend_request()
returns trigger language plpgsql security definer set search_path = ''
as $$
declare v_uid uuid := (select auth.uid()); v_now timestamptz := clock_timestamp();
begin
  if tg_op = 'INSERT' then
    if new.sender_id is null or new.receiver_id is null or new.sender_id = new.receiver_id then
      raise exception 'invalid friend request' using errcode = '22023';
    end if;
    if v_uid is not null then perform private.consume_action_limit(v_uid, 'friend_requests', 600, 3, 86400, 15); end if;
    new.status := 'pending'; new.created_at := v_now; new.responded_at := null;
    return new;
  end if;
  if new.id is distinct from old.id or new.sender_id is distinct from old.sender_id
     or new.receiver_id is distinct from old.receiver_id or new.created_at is distinct from old.created_at
     or old.status <> 'pending' or new.status <> 'accepted' or old.receiver_id <> v_uid then
    raise exception 'invalid friend request transition' using errcode = '42501';
  end if;
  new.responded_at := v_now;
  return new;
end;
$$;
revoke all on function private.guard_friend_request() from public, anon, authenticated;
drop trigger if exists cipher_guard_friend_requests_insert on public.friend_requests;
create trigger cipher_guard_friend_requests_insert before insert on public.friend_requests
for each row execute function private.guard_friend_request();
drop trigger if exists cipher_guard_friend_requests_update on public.friend_requests;
create trigger cipher_guard_friend_requests_update before update on public.friend_requests
for each row execute function private.guard_friend_request();

drop policy if exists "friend_requests_update" on public.friend_requests;
create policy "friend_requests_update" on public.friend_requests for update to authenticated
using (receiver_id = (select auth.uid()) and status = 'pending')
with check (receiver_id = (select auth.uid()) and status = 'accepted');
drop policy if exists "friend_requests_insert" on public.friend_requests;
create policy "friend_requests_insert" on public.friend_requests for insert to authenticated
with check (sender_id = (select auth.uid()) and receiver_id <> (select auth.uid()));

commit;
