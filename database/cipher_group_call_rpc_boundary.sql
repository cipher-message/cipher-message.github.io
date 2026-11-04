-- Harden group-call RPC exposure: keep privileged implementations in private,
-- expose only SECURITY INVOKER wrappers in public.
begin;

-- The deployed definitions are managed in Supabase migration history.
-- This file documents the boundary change made for Cipher group calls.

revoke all on function public.get_group_call(uuid) from public, anon;
revoke all on function public.group_call_state(uuid,uuid,boolean,boolean,boolean,boolean) from public, anon;
revoke all on function public.join_group_call(uuid,boolean) from public, anon;
revoke all on function public.leave_group_call(uuid) from public, anon;
revoke all on function public.send_group_call_signal(uuid,uuid,jsonb) from public, anon;

grant execute on function public.get_group_call(uuid) to authenticated;
grant execute on function public.group_call_state(uuid,uuid,boolean,boolean,boolean,boolean) to authenticated;
grant execute on function public.join_group_call(uuid,boolean) to authenticated;
grant execute on function public.leave_group_call(uuid) to authenticated;
grant execute on function public.send_group_call_signal(uuid,uuid,jsonb) to authenticated;

commit;
