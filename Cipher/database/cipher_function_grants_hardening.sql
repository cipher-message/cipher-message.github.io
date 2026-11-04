-- Narrow function-exposure fix. Keep only RPCs needed by authenticated clients;
-- trigger and maintenance functions remain callable by their trusted owners.
begin;

revoke execute on function public.enforce_allowed_email_domains() from public, anon, authenticated;
revoke execute on function public.purge_expired_statuses() from public, anon, authenticated;
revoke execute on function public.purge_expired_messages() from public, anon, authenticated;
revoke execute on function public.rls_auto_enable() from public, anon, authenticated;
revoke execute on function public.set_message_expiry() from public, anon, authenticated;

revoke execute on function public.delete_own_account() from public, anon, authenticated;
grant execute on function public.delete_own_account() to authenticated;

revoke execute on function public.is_channel_member(uuid) from public, anon, authenticated;
grant execute on function public.is_channel_member(uuid) to authenticated, service_role;

commit;
