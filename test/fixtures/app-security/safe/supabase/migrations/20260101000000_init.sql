create table public.profiles (
  id uuid primary key references auth.users,
  full_name text
);
alter table public.profiles enable row level security;

create policy "owners update their profile" on profiles for update
  using (auth.uid() = id) with check (auth.uid() = id);
create policy "profiles are public to read" on profiles for select using (true);
create policy "service role manages profiles" on profiles for all to service_role using (true);

-- create table scratch (x int);
/* create table also_commented (x int); */
create function public.touch() returns void language sql as $$
  create table inside_function_body (x int);
$$;

create table private.audit_log (id bigint primary key, detail text);
