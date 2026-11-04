-- Per-user AI spending guard, called by cipher-ai only after user and channel
-- membership checks succeed.
begin;

create or replace function public.consume_cipher_ai_rate_limit()
returns void language plpgsql security definer set search_path = ''
as $$
declare v_uid uuid := (select auth.uid());
begin
  if v_uid is null then raise exception 'not authenticated' using errcode = '42501'; end if;
  perform private.consume_action_limit(v_uid, 'cipher_ai', 60, 6, 86400, 40);
end;
$$;
revoke all on function public.consume_cipher_ai_rate_limit() from public, anon;
grant execute on function public.consume_cipher_ai_rate_limit() to authenticated;

commit;
