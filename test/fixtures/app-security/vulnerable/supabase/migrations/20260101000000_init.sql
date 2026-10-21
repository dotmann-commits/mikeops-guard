create table public.profiles (
  id uuid primary key references auth.users,
  full_name text
);

create table notes (
  id bigint generated always as identity primary key,
  owner uuid not null,
  body text
);
