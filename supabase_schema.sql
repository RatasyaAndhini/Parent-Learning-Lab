-- Parent Companion schema compatible with the application.
-- Run in Supabase SQL Editor. The app uses Supabase Auth; it never reads
-- parents.password_hash from the browser.

create extension if not exists pgcrypto;

create table if not exists public.parents (
    id uuid primary key default gen_random_uuid(),
    name varchar(100) not null,
    email varchar(100) unique not null,
    password_hash varchar(255) not null,
    created_at timestamptz default current_timestamp
);

create table if not exists public.children (
    id uuid primary key default gen_random_uuid(),
    parent_id uuid references public.parents(id) on delete cascade,
    nickname varchar(50) not null,
    birth_date date not null,
    interests text[],
    learning_focus text[],
    available_time integer default 20,
    created_at timestamptz default current_timestamp
);

create table if not exists public.activities (
    id uuid primary key default gen_random_uuid(),
    title varchar(150) not null,
    description text not null,
    category varchar(50) not null,
    min_age integer not null,
    max_age integer not null,
    duration_minutes integer not null,
    materials text[] not null,
    steps text[] not null,
    parent_tips text,
    variations text,
    learning_goal text,
    created_at timestamptz default current_timestamp
);

create table if not exists public.activity_logs (
    id uuid primary key default gen_random_uuid(),
    child_id uuid references public.children(id) on delete cascade,
    activity_id uuid references public.activities(id) on delete cascade,
    status varchar(30) default 'planned',
    scheduled_date date default current_date,
    completed_at timestamptz,
    created_at timestamptz default current_timestamp
);

create table if not exists public.journal_entries (
    id uuid primary key default gen_random_uuid(),
    child_id uuid references public.children(id) on delete cascade,
    activity_id uuid references public.activities(id) on delete set null,
    entry_date date default current_date,
    notes text not null,
    engagement_level varchar(30),
    milestone_tag varchar(100),
    photo_url text,
    created_at timestamptz default current_timestamp
);

create table if not exists public.milestones (
    id uuid primary key default gen_random_uuid(),
    domain varchar(50) not null,
    age_group varchar(50) not null,
    description text not null,
    created_at timestamptz default current_timestamp
);

create index if not exists children_parent_id_idx on public.children(parent_id);
create index if not exists activity_logs_child_id_idx on public.activity_logs(child_id);
create index if not exists journal_entries_child_id_idx on public.journal_entries(child_id);

alter table public.parents enable row level security;
alter table public.children enable row level security;
alter table public.activities enable row level security;
alter table public.activity_logs enable row level security;
alter table public.journal_entries enable row level security;
alter table public.milestones enable row level security;

drop policy if exists "Allow public all parents" on public.parents;
drop policy if exists "Allow public all children" on public.children;
drop policy if exists "Allow public all activities" on public.activities;
drop policy if exists "Allow public all activity logs" on public.activity_logs;
drop policy if exists "Allow public all journal entries" on public.journal_entries;
drop policy if exists "Allow public all milestones" on public.milestones;

drop policy if exists "Parents can read their own profile" on public.parents;
create policy "Parents can read their own profile"
    on public.parents for select to authenticated
    using (lower(email) = lower(auth.jwt() ->> 'email'));

drop policy if exists "Parents can create their own profile" on public.parents;
create policy "Parents can create their own profile"
    on public.parents for insert to authenticated
    with check (
        id = auth.uid()
        and lower(email) = lower(auth.jwt() ->> 'email')
    );

grant select, insert on public.parents to authenticated;

drop policy if exists "Parents can read their own children" on public.children;
create policy "Parents can read their own children"
    on public.children for select to authenticated
    using (exists (
        select 1 from public.parents p
        where p.id = children.parent_id
          and lower(p.email) = lower(auth.jwt() ->> 'email')
    ));

drop policy if exists "Parents can read their children's journals" on public.journal_entries;
create policy "Parents can read their children's journals"
    on public.journal_entries for select to authenticated
    using (exists (
        select 1 from public.children c
        join public.parents p on p.id = c.parent_id
        where c.id = journal_entries.child_id
          and lower(p.email) = lower(auth.jwt() ->> 'email')
    ));

drop policy if exists "Parents can add their children's journals" on public.journal_entries;
create policy "Parents can add their children's journals"
    on public.journal_entries for insert to authenticated
    with check (exists (
        select 1 from public.children c
        join public.parents p on p.id = c.parent_id
        where c.id = journal_entries.child_id
          and lower(p.email) = lower(auth.jwt() ->> 'email')
    ));

drop policy if exists "Parents can read their children's activity logs" on public.activity_logs;
create policy "Parents can read their children's activity logs"
    on public.activity_logs for select to authenticated
    using (exists (
        select 1 from public.children c
        join public.parents p on p.id = c.parent_id
        where c.id = activity_logs.child_id
          and lower(p.email) = lower(auth.jwt() ->> 'email')
    ));

drop policy if exists "Parents can add their children's activity logs" on public.activity_logs;
create policy "Parents can add their children's activity logs"
    on public.activity_logs for insert to authenticated
    with check (exists (
        select 1 from public.children c
        join public.parents p on p.id = c.parent_id
        where c.id = activity_logs.child_id
          and lower(p.email) = lower(auth.jwt() ->> 'email')
    ));

drop policy if exists "Activity catalog is readable" on public.activities;
create policy "Activity catalog is readable"
    on public.activities for select to anon, authenticated using (true);

drop policy if exists "Authenticated users can add catalog activities" on public.activities;
create policy "Authenticated users can add catalog activities"
    on public.activities for insert to authenticated with check (true);

drop policy if exists "Milestones are readable" on public.milestones;
create policy "Milestones are readable"
    on public.milestones for select to anon, authenticated using (true);

-- Provision Auth users in Supabase Authentication and matching parent profiles
-- with a trusted admin workflow. The app authenticates only through Supabase Auth;
-- never store a real password or its hash in public.parents.password_hash.
-- If that required legacy column must be populated, use a non-secret marker such
-- as 'managed-by-supabase-auth'. Add each child with that parent's UUID.
