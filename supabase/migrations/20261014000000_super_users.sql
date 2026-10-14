create table if not exists public.super_users (
    user_id    uuid primary key references auth.users (id) on delete cascade,
    email      text not null,
    granted_by uuid references auth.users (id) on delete set null,
    created_at timestamptz not null default now()
);

alter table public.super_users enable row level security;

create or replace function public.is_super_user()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
    select exists (select 1 from public.super_users where user_id = auth.uid());
$$;

revoke all on function public.is_super_user() from public;
grant execute on function public.is_super_user() to anon, authenticated;

-- Super users can see the registry. No direct writes: use the RPCs below.
drop policy if exists "super_users_select" on public.super_users;
create policy "super_users_select" on public.super_users
    for select to authenticated
    using (public.is_super_user());

-- 2. MANAGEMENT RPCs (callable from the Command Center) ------------------------

-- Every account (club members + super users) for the Super Users tab.
create or replace function public.admin_list_users()
returns table (user_id uuid, email text, full_name text, is_super boolean, created_at timestamptz)
language plpgsql
stable
security definer
set search_path = public
as $$
begin
    if not public.is_super_user() then
        raise exception 'Super user access required' using errcode = '42501';
    end if;
    return query
        select u.id,
               u.email::text,
               coalesce(m.full_name, u.raw_user_meta_data ->> 'full_name')::text,
               (s.user_id is not null),
               u.created_at
        from auth.users u
        left join public.members m on m.id = u.id
        left join public.super_users s on s.user_id = u.id
        order by (s.user_id is not null) desc, u.email;
end;
$$;

create or replace function public.grant_super_user(target_email text)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
    target_id uuid;
begin
    if not public.is_super_user() then
        raise exception 'Super user access required' using errcode = '42501';
    end if;
    select id into target_id from auth.users where lower(email) = lower(trim(target_email));
    if target_id is null then
        raise exception 'No account found for %', target_email;
    end if;
    insert into public.super_users (user_id, email, granted_by)
    values (target_id, lower(trim(target_email)), auth.uid())
    on conflict (user_id) do nothing;
end;
$$;

create or replace function public.revoke_super_user(target_user_id uuid)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
    if not public.is_super_user() then
        raise exception 'Super user access required' using errcode = '42501';
    end if;
    if target_user_id = auth.uid() then
        raise exception 'You cannot revoke your own super user access';
    end if;
    delete from public.super_users where user_id = target_user_id;
end;
$$;

revoke all on function public.admin_list_users() from public;
revoke all on function public.grant_super_user(text) from public;
revoke all on function public.revoke_super_user(uuid) from public;
grant execute on function public.admin_list_users() to authenticated;
grant execute on function public.grant_super_user(text) to authenticated;
grant execute on function public.revoke_super_user(uuid) to authenticated;

-- 3. OPS TABLES: public read, super-user-only writes ---------------------------
-- Permissive policies guarantee the access the sites need; RESTRICTIVE policies
-- cap writes to super users even if older permissive policies are still around.

do $$
declare
    t text;
begin
    foreach t in array array['booking_sessions', 'booking_locations', 'booking_addons', 'booking_config', 'site_pass_tiers']
    loop
        execute format('alter table public.%I enable row level security', t);

        execute format('drop policy if exists "public_read" on public.%I', t);
        execute format('create policy "public_read" on public.%I for select to anon, authenticated using (true)', t);

        execute format('drop policy if exists "super_user_write" on public.%I', t);
        execute format('create policy "super_user_write" on public.%I for all to authenticated using (public.is_super_user()) with check (public.is_super_user())', t);

        execute format('drop policy if exists "only_super_insert" on public.%I', t);
        execute format('create policy "only_super_insert" on public.%I as restrictive for insert to anon, authenticated with check (public.is_super_user())', t);

        execute format('drop policy if exists "only_super_update" on public.%I', t);
        execute format('create policy "only_super_update" on public.%I as restrictive for update to anon, authenticated using (public.is_super_user()) with check (public.is_super_user())', t);

        execute format('drop policy if exists "only_super_delete" on public.%I', t);
        execute format('create policy "only_super_delete" on public.%I as restrictive for delete to anon, authenticated using (public.is_super_user())', t);
    end loop;
end;
$$;

-- 4. SITE PASS REQUESTS: members submit + see their own, super users manage all

alter table public.site_pass_requests enable row level security;

drop policy if exists "member_insert_own" on public.site_pass_requests;
create policy "member_insert_own" on public.site_pass_requests
    for insert to authenticated
    with check (member_id = auth.uid());

drop policy if exists "member_or_super_select" on public.site_pass_requests;
create policy "member_or_super_select" on public.site_pass_requests
    for select to authenticated
    using (member_id = auth.uid() or public.is_super_user());

drop policy if exists "super_user_write" on public.site_pass_requests;
create policy "super_user_write" on public.site_pass_requests
    for all to authenticated
    using (public.is_super_user()) with check (public.is_super_user());

drop policy if exists "only_own_or_super_select" on public.site_pass_requests;
create policy "only_own_or_super_select" on public.site_pass_requests
    as restrictive for select to anon, authenticated
    using (member_id = auth.uid() or public.is_super_user());

drop policy if exists "only_own_or_super_insert" on public.site_pass_requests;
create policy "only_own_or_super_insert" on public.site_pass_requests
    as restrictive for insert to anon, authenticated
    with check (member_id = auth.uid() or public.is_super_user());

drop policy if exists "only_super_update" on public.site_pass_requests;
create policy "only_super_update" on public.site_pass_requests
    as restrictive for update to anon, authenticated
    using (public.is_super_user()) with check (public.is_super_user());

drop policy if exists "only_super_delete" on public.site_pass_requests;
create policy "only_super_delete" on public.site_pass_requests
    as restrictive for delete to anon, authenticated
    using (public.is_super_user());

-- 5. BOOTSTRAP FIRST SUPER USER ----------------------------------------------
-- The account must already exist (Authentication > Users > Add user).

do $$
declare
    first_email constant text := 'sarithadissanayake1@gmail.com';
    uid uuid;
begin
    select id into uid from auth.users where lower(email) = first_email;
    if uid is null then
        raise exception 'Account % not found. Create it in Authentication > Users > Add user (tick Auto Confirm), then re-run this script.', first_email;
    end if;
    insert into public.super_users (user_id, email) values (uid, first_email)
    on conflict (user_id) do nothing;
end;
$$;
