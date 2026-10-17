
create table if not exists public.contact_inquiries (
    id           uuid primary key default gen_random_uuid(),
    name         text not null check (char_length(name) between 1 and 120),
    email        text not null check (char_length(email) between 3 and 254),
    phone        text check (phone is null or char_length(phone) <= 40),
    inquiry_type text not null default 'general' check (char_length(inquiry_type) <= 40),
    message      text not null check (char_length(message) between 1 and 5000),
    status       text not null default 'new' check (status in ('new', 'in_progress', 'resolved', 'archived')),
    admin_note   text check (admin_note is null or char_length(admin_note) <= 2000),
    created_at   timestamptz not null default now()
);

create table if not exists public.events (
    id                uuid primary key default gen_random_uuid(),
    slug              text not null unique check (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$'),
    name              text not null check (char_length(name) between 1 and 120),
    location          text check (location is null or char_length(location) <= 200),
    starts_at         timestamptz,
    ends_at           timestamptz,
    registration_open boolean not null default true,
    created_at        timestamptz not null default now()
);

create table if not exists public.event_registrations (
    id          uuid primary key default gen_random_uuid(),
    event_id    uuid not null references public.events (id) on delete cascade,
    full_name   text not null check (char_length(full_name) between 1 and 120),
    email       text not null check (char_length(email) between 3 and 254),
    phone       text not null check (char_length(phone) between 5 and 40),
    flight_type text not null check (flight_type in ('tandem-passenger', 'solo-pilot', 'media-creator', 'group-booking')),
    status      text not null default 'pending' check (status in ('pending', 'contacted', 'confirmed', 'cancelled')),
    admin_note  text check (admin_note is null or char_length(admin_note) <= 2000),
    created_at  timestamptz not null default now()
);

create index if not exists contact_inquiries_created_idx on public.contact_inquiries (created_at desc);
create index if not exists event_registrations_event_idx on public.event_registrations (event_id, created_at desc);
-- One sign-up per email per event; signing up again updates the existing row.
create unique index if not exists event_registrations_event_email_key on public.event_registrations (event_id, lower(email));

-- Renames the earlier "ambuluwawa-2027" placeholder if this file was already run once.
update public.events
set slug = 'paragliding-festival-2027', name = 'International Paragliding Festival 2027', location = 'Kandy (Ambuluwawa & 18 Bends)',
    starts_at = '2027-02-26 07:00+05:30', ends_at = '2027-03-02 18:00+05:30'
where slug = 'ambuluwawa-2027'
  and not exists (select 1 from public.events where slug = 'paragliding-festival-2027');

insert into public.events (slug, name, location, starts_at, ends_at)
values ('paragliding-festival-2027', 'International Paragliding Festival 2027', 'Kandy (Ambuluwawa & 18 Bends)', '2027-02-26 07:00+05:30', '2027-03-02 18:00+05:30')
on conflict (slug) do nothing;

-- 2. ACCESS RULES ------------------------------------------------------------------

alter table public.contact_inquiries enable row level security;
alter table public.events enable row level security;
alter table public.event_registrations enable row level security;

do $$
declare
    t text;
begin
    foreach t in array array['contact_inquiries', 'events', 'event_registrations']
    loop
        execute format('drop policy if exists "super_user_all" on public.%I', t);
        execute format('create policy "super_user_all" on public.%I for all to authenticated using (public.is_super_user()) with check (public.is_super_user())', t);

        execute format('drop policy if exists "only_super_insert" on public.%I', t);
        execute format('create policy "only_super_insert" on public.%I as restrictive for insert to anon, authenticated with check (public.is_super_user())', t);

        execute format('drop policy if exists "only_super_update" on public.%I', t);
        execute format('create policy "only_super_update" on public.%I as restrictive for update to anon, authenticated using (public.is_super_user()) with check (public.is_super_user())', t);

        execute format('drop policy if exists "only_super_delete" on public.%I', t);
        execute format('create policy "only_super_delete" on public.%I as restrictive for delete to anon, authenticated using (public.is_super_user())', t);

        execute format('drop trigger if exists csfa_audit on public.%I', t);
        execute format('create trigger csfa_audit after insert or update or delete on public.%I for each row execute function public.csfa_audit_row()', t);
    end loop;
end;
$$;

-- 3. PUBLIC SUBMISSION RPCs ----------------------------------------------------------

create or replace function public.submit_contact_inquiry(
    p_name text, p_email text, p_phone text, p_type text, p_message text
)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
    v_email text := lower(trim(p_email));
begin
    if coalesce(trim(p_name), '') = '' or coalesce(trim(p_message), '') = '' then
        raise exception 'Name and message are required' using errcode = '22023';
    end if;
    if v_email !~ '^[^@\s]+@[^@\s]+\.[^@\s]+$' then
        raise exception 'Invalid email address' using errcode = '22023';
    end if;
    -- Basic flood guard: at most 3 messages per email address in 10 minutes.
    if (select count(*) from public.contact_inquiries
        where lower(email) = v_email and created_at > now() - interval '10 minutes') >= 3 then
        raise exception 'Too many messages. Please try again later.' using errcode = '54000';
    end if;

    insert into public.contact_inquiries (name, email, phone, inquiry_type, message)
    values (trim(p_name), v_email, nullif(trim(coalesce(p_phone, '')), ''), coalesce(nullif(trim(p_type), ''), 'general'), trim(p_message));
end;
$$;

create or replace function public.register_for_event(
    p_event_slug text, p_full_name text, p_email text, p_phone text, p_flight_type text
)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
    v_event uuid;
    v_email text := lower(trim(p_email));
begin
    select id into v_event from public.events where slug = p_event_slug and registration_open;
    if v_event is null then
        raise exception 'Registration for this event is closed' using errcode = '22023';
    end if;
    if coalesce(trim(p_full_name), '') = '' or coalesce(trim(p_phone), '') = '' then
        raise exception 'Name and phone are required' using errcode = '22023';
    end if;
    if v_email !~ '^[^@\s]+@[^@\s]+\.[^@\s]+$' then
        raise exception 'Invalid email address' using errcode = '22023';
    end if;

    insert into public.event_registrations (event_id, full_name, email, phone, flight_type)
    values (v_event, trim(p_full_name), v_email, trim(p_phone), p_flight_type)
    on conflict (event_id, lower(email)) do update
        set full_name = excluded.full_name, phone = excluded.phone, flight_type = excluded.flight_type;
end;
$$;

revoke all on function public.submit_contact_inquiry(text, text, text, text, text) from public;
revoke all on function public.register_for_event(text, text, text, text, text) from public;
grant execute on function public.submit_contact_inquiry(text, text, text, text, text) to anon, authenticated;
grant execute on function public.register_for_event(text, text, text, text, text) to anon, authenticated;
