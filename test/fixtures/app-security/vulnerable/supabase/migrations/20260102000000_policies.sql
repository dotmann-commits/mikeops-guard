alter table notes enable row level security;

create policy "anyone signed in can edit notes" on notes for update to authenticated using (true);

create policy "public contact form" on contact_messages for insert to anon with check (true);
