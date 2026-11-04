-- Storage policy hardening: only channel readers or status viewers may read
-- attachments; uploads must use message/status-owned paths; object renames stay
-- inside the caller's own avatar/background folder.
begin;

drop policy if exists "attachments_storage_read" on storage.objects;
create policy "attachments_storage_read" on storage.objects for select to authenticated
using (
  bucket_id = 'attachments' and (
    exists (
      select 1 from public.messages m
      where m.channel_id::text = split_part(name, '/', 1)
        and m.id::text = split_part(name, '/', 2)
        and is_channel_member(m.channel_id)
    )
    or exists (
      select 1 from public.statuses s
      where s.storage_path = name and s.expires_at > now()
        and (s.user_id = (select auth.uid()) or exists (
          select 1 from public.channel_members mine
          join public.channel_members them on them.channel_id = mine.channel_id
          join public.channels c on c.id = mine.channel_id
          where mine.user_id = (select auth.uid()) and them.user_id = s.user_id and c.type = 'dm'
        ))
        and not exists (
          select 1 from public.blocks b
          where (b.blocker_id = (select auth.uid()) and b.blocked_id = s.user_id)
             or (b.blocker_id = s.user_id and b.blocked_id = (select auth.uid()))
        )
    )
  )
);

drop policy if exists "attachments_storage_write" on storage.objects;
create policy "attachments_storage_write" on storage.objects for insert to authenticated
with check (
  bucket_id = 'attachments' and (
    exists (
      select 1 from public.messages m
      where m.channel_id::text = split_part(name, '/', 1)
        and m.id::text = split_part(name, '/', 2)
        and m.sender_id = (select auth.uid())
        and is_channel_member(m.channel_id)
    )
    or (split_part(name, '/', 1) = 'status' and split_part(name, '/', 2) = (select auth.uid())::text)
  )
);

drop policy if exists "avatars_update_own" on storage.objects;
create policy "avatars_update_own" on storage.objects for update to authenticated
using (bucket_id = 'avatars' and (storage.foldername(name))[1] = (select auth.uid())::text)
with check (bucket_id = 'avatars' and (storage.foldername(name))[1] = (select auth.uid())::text);

drop policy if exists "chatbg_select_own" on storage.objects;
create policy "chatbg_select_own" on storage.objects for select to authenticated
using (
  bucket_id = 'chat-backgrounds' and (
    split_part(name, '/', 1) = (select auth.uid())::text
    or exists (select 1 from public.channels c where c.background ->> 'path' = name and is_channel_member(c.id))
  )
);
drop policy if exists "chatbg_insert_own" on storage.objects;
create policy "chatbg_insert_own" on storage.objects for insert to authenticated
with check (bucket_id = 'chat-backgrounds' and split_part(name, '/', 1) = (select auth.uid())::text);
drop policy if exists "chatbg_update_own" on storage.objects;
create policy "chatbg_update_own" on storage.objects for update to authenticated
using (bucket_id = 'chat-backgrounds' and split_part(name, '/', 1) = (select auth.uid())::text)
with check (bucket_id = 'chat-backgrounds' and split_part(name, '/', 1) = (select auth.uid())::text);

update storage.buckets set file_size_limit = 26214400 where id = 'attachments';
update storage.buckets
set file_size_limit = 5242880,
    allowed_mime_types = array['image/jpeg', 'image/png', 'image/webp', 'image/gif']
where id = 'avatars';
update storage.buckets
set file_size_limit = 15728640,
    allowed_mime_types = array['image/jpeg', 'image/png', 'image/webp', 'image/gif']
where id = 'chat-backgrounds';

commit;
