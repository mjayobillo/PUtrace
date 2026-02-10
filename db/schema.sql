create extension if not exists "pgcrypto";

create table if not exists public.users (
  id uuid primary key default gen_random_uuid(),
  full_name text not null,
  email text not null unique,
  password_hash text not null,
  contact_phone text,
  created_at timestamptz not null default now()
);

create table if not exists public.items (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.users(id) on delete cascade,
  item_name text not null,
  item_description text,
  category text default 'Other',
  item_status text not null default 'active',
  image_url text,
  token text not null unique,
  qr_data_url text not null,
  created_at timestamptz not null default now()
);

create table if not exists public.finder_reports (
  id bigserial primary key,
  item_id uuid not null references public.items(id) on delete cascade,
  finder_name text not null,
  finder_email text not null,
  location_hint text,
  message text not null,
  status text not null default 'open',
  created_at timestamptz not null default now()
);
