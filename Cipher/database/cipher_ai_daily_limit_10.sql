create or replace function public.consume_cipher_ai_rate_limit()
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_uid uuid := (select auth.uid());
begin
  if v_uid is null then
    raise exception 'not authenticated' using errcode = '42501';
  end if;
  -- Keep the burst cap and limit each account to ten requests per UTC day.
  perform private.consume_action_limit(v_uid, 'cipher_ai', 60, 6, 86400, 10);
end;
$$;
