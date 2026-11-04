-- Pin function name resolution and preserve caller-scoped membership semantics.
begin;

create or replace function public.is_channel_member(cid uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.channel_members cm
    where cm.channel_id = cid and cm.user_id = (select auth.uid())
  );
$$;
revoke all on function public.is_channel_member(uuid) from public, anon;
grant execute on function public.is_channel_member(uuid) to authenticated, service_role;

create or replace function public.enforce_allowed_email_domains()
returns trigger
language plpgsql
security invoker
set search_path = ''
as $$
begin
  if new.email is null or lower(split_part(new.email, '@', 2)) not in
     ('yahoo.com', 'gmail.com', 'icloud.com', 'schools.sa.edu.au') then
    raise exception 'Email domain not allowed.';
  end if;
  return new;
end;
$$;
revoke all on function public.enforce_allowed_email_domains() from public, anon, authenticated;

commit;
