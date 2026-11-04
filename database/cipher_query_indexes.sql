-- Cover unindexed foreign keys reported by the Supabase performance advisor.
-- These indexes help joins and referenced-row updates/deletes as Cipher grows.
create index if not exists idx_call_rate_limits_peer_id on private.call_rate_limits (peer_id);
create index if not exists idx_blocks_blocked_id on public.blocks (blocked_id);
create index if not exists idx_bookmarks_message_id on public.bookmarks (message_id);
create index if not exists idx_channel_members_user_id on public.channel_members (user_id);
create index if not exists idx_channels_created_by on public.channels (created_by);
create index if not exists idx_focus_participants_user_id on public.focus_participants (user_id);
create index if not exists idx_focus_sessions_started_by on public.focus_sessions (started_by);
create index if not exists idx_friend_requests_receiver_id on public.friend_requests (receiver_id);
create index if not exists idx_message_hides_message_id on public.message_hides (message_id);
create index if not exists idx_pins_pinned_by on public.pins (pinned_by);
create index if not exists idx_reactions_user_id on public.reactions (user_id);
create index if not exists idx_reports_reporter_id on public.reports (reporter_id);
create index if not exists idx_status_views_status_id on public.status_views (status_id);
