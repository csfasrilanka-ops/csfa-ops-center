alter table public.members
    add column if not exists membership_status         text,
    add column if not exists email                     text,
    add column if not exists date_of_birth             date,
    add column if not exists nic_passport_no           text,
    add column if not exists address                   text,
    add column if not exists blood_type                text,
    add column if not exists weight_kg                 integer,
    add column if not exists medical_conditions        text,
    add column if not exists license_expiry            date,
    add column if not exists years_flying              integer,
    add column if not exists total_flight_hours        integer,
    add column if not exists reserve_repack_date       date,
    add column if not exists insurance_provider        text,
    add column if not exists insurance_policy_no       text,
    add column if not exists insurance_expiry          date,
    add column if not exists emergency_contact_relation text,
    add column if not exists avatar_path               text,
    add column if not exists waiver_accepted_at        timestamptz,
    add column if not exists applied_at                timestamptz not null default now(),
    add column if not exists reviewed_by               uuid references auth.users (id) on delete set null,
    add column if not exists reviewed_at               timestamptz,
    add column if not exists review_note               text;

-- Normalise status values. Existing NULLs become 'pending' and show up in the
-- Command Center's Pending tab for a super user to approve.
alter table public.members alter column membership_status set default 'pending';
update public.members set membership_status = lower(coalesce(membership_status, 'pending'));
update public.members m set email = u.email from auth.users u where u.id = m.id and m.email is null;

alter table public.members drop constraint if exists members_membership_status_check;
alter table public.members add constraint members_membership_status_check
    check (membership_status in ('pending', 'active', 'rejected', 'suspended'));

alter table public.members drop constraint if exists members_blood_type_check;
alter table public.members add constraint members_blood_type_check
    check (blood_type is null or blood_type in ('A+', 'A-', 'B+', 'B-', 'AB+', 'AB-', 'O+', 'O-', 'Unknown'));

-- 2. HELPERS -------------------------------------------------------------------

create or replace function public.is_active_member()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
    select exists (select 1 from public.members where id = auth.uid() and membership_status = 'active');
$$;

revoke all on function public.is_active_member() from public;
grant execute on function public.is_active_member() to anon, authenticated;

create or replace function public.try_date(v text)
returns date
language plpgsql
immutable
as $$
begin
    return nullif(trim(v), '')::date;
exception when others then
    return null;
end;
$$;

create or replace function public.try_int(v text)
returns integer
language plpgsql
immutable
as $$
begin
    return nullif(trim(v), '')::integer;
exception when others then
    return null;
end;
$$;

-- 3. SIGNUP -> PENDING APPLICATION ---------------------------------------------
-- Copies the signup form (auth user metadata) into members. Named zz_ so it runs
-- after any older "create profile" trigger and fills in the rest of the row.

create or replace function public.csfa_create_member_application()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
    meta jsonb := coalesce(new.raw_user_meta_data, '{}'::jsonb);
begin
    insert into public.members as m (
        id, email, full_name, phone_number, country, pilot_rating,
        date_of_birth, nic_passport_no, address, blood_type, weight_kg, medical_conditions,
        appi_license_no, fai_license_no, license_expiry, years_flying, total_flight_hours,
        glider_brand_model, reserve_repack_date,
        insurance_provider, insurance_policy_no, insurance_expiry,
        emergency_contact_name, emergency_contact_relation, emergency_contact_phone,
        waiver_accepted_at, membership_status, applied_at
    ) values (
        new.id, new.email, meta ->> 'full_name', meta ->> 'phone_number', meta ->> 'country', meta ->> 'pilot_rating',
        public.try_date(meta ->> 'date_of_birth'), meta ->> 'nic_passport_no', meta ->> 'address',
        case when meta ->> 'blood_type' in ('A+', 'A-', 'B+', 'B-', 'AB+', 'AB-', 'O+', 'O-', 'Unknown') then meta ->> 'blood_type' end,
        public.try_int(meta ->> 'weight_kg'), meta ->> 'medical_conditions',
        meta ->> 'appi_license_no', meta ->> 'fai_license_no', public.try_date(meta ->> 'license_expiry'),
        public.try_int(meta ->> 'years_flying'), public.try_int(meta ->> 'total_flight_hours'),
        meta ->> 'glider_brand_model', public.try_date(meta ->> 'reserve_repack_date'),
        meta ->> 'insurance_provider', meta ->> 'insurance_policy_no', public.try_date(meta ->> 'insurance_expiry'),
        meta ->> 'emergency_contact_name', meta ->> 'emergency_contact_relation', meta ->> 'emergency_contact_phone',
        case when (meta ->> 'waiver_accepted') = 'true' then now() end,
        'pending', now()
    )
    on conflict (id) do update set
        email = excluded.email,
        full_name = coalesce(excluded.full_name, m.full_name),
        phone_number = excluded.phone_number,
        country = excluded.country,
        pilot_rating = excluded.pilot_rating,
        date_of_birth = excluded.date_of_birth,
        nic_passport_no = excluded.nic_passport_no,
        address = excluded.address,
        blood_type = excluded.blood_type,
        weight_kg = excluded.weight_kg,
        medical_conditions = excluded.medical_conditions,
        appi_license_no = excluded.appi_license_no,
        fai_license_no = excluded.fai_license_no,
        license_expiry = excluded.license_expiry,
        years_flying = excluded.years_flying,
        total_flight_hours = excluded.total_flight_hours,
        glider_brand_model = excluded.glider_brand_model,
        reserve_repack_date = excluded.reserve_repack_date,
        insurance_provider = excluded.insurance_provider,
        insurance_policy_no = excluded.insurance_policy_no,
        insurance_expiry = excluded.insurance_expiry,
        emergency_contact_name = excluded.emergency_contact_name,
        emergency_contact_relation = excluded.emergency_contact_relation,
        emergency_contact_phone = excluded.emergency_contact_phone,
        waiver_accepted_at = excluded.waiver_accepted_at,
        membership_status = 'pending',
        applied_at = now();
    return new;
end;
$$;

drop trigger if exists zz_csfa_member_application on auth.users;
create trigger zz_csfa_member_application
    after insert on auth.users
    for each row execute function public.csfa_create_member_application();

-- 4. MEMBERS CAN'T APPROVE THEMSELVES ------------------------------------------
-- Signed-in non-super users can edit their profile but never the review fields.

create or replace function public.csfa_guard_member_review_fields()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
    if auth.uid() is null or public.is_super_user() then
        return new;
    end if;
    if tg_op = 'INSERT' then
        new.membership_status := 'pending';
        new.reviewed_by := null;
        new.reviewed_at := null;
        new.review_note := null;
        new.applied_at := now();
    else
        new.id := old.id;
        new.email := old.email;
        new.membership_status := old.membership_status;
        new.reviewed_by := old.reviewed_by;
        new.reviewed_at := old.reviewed_at;
        new.review_note := old.review_note;
        new.applied_at := old.applied_at;
    end if;
    -- Photos must come from the member's own storage folder.
    if new.avatar_path is not null and new.avatar_path not like auth.uid()::text || '/%' then
        new.avatar_path := case when tg_op = 'UPDATE' then old.avatar_path end;
    end if;
    return new;
end;
$$;

drop trigger if exists csfa_guard_member_review_fields on public.members;
create trigger csfa_guard_member_review_fields
    before insert or update on public.members
    for each row execute function public.csfa_guard_member_review_fields();

-- 5. MEMBERS RLS: own row + super users only ----------------------------------
-- Sensitive data (blood type, medical, ID numbers) is no longer readable by other
-- members. The club directory uses member_directory() which returns safe columns.

alter table public.members enable row level security;

drop policy if exists "member_select_own" on public.members;
create policy "member_select_own" on public.members
    for select to authenticated
    using (id = auth.uid() or public.is_super_user());

drop policy if exists "member_update_own" on public.members;
create policy "member_update_own" on public.members
    for update to authenticated
    using (id = auth.uid() or public.is_super_user())
    with check (id = auth.uid() or public.is_super_user());

drop policy if exists "member_insert_own" on public.members;
create policy "member_insert_own" on public.members
    for insert to authenticated
    with check (id = auth.uid() or public.is_super_user());

drop policy if exists "super_user_delete" on public.members;
create policy "super_user_delete" on public.members
    for delete to authenticated
    using (public.is_super_user());

drop policy if exists "only_own_or_super_select" on public.members;
create policy "only_own_or_super_select" on public.members
    as restrictive for select to anon, authenticated
    using (id = auth.uid() or public.is_super_user());

drop policy if exists "only_own_or_super_insert" on public.members;
create policy "only_own_or_super_insert" on public.members
    as restrictive for insert to anon, authenticated
    with check (id = auth.uid() or public.is_super_user());

drop policy if exists "only_own_or_super_update" on public.members;
create policy "only_own_or_super_update" on public.members
    as restrictive for update to anon, authenticated
    using (id = auth.uid() or public.is_super_user())
    with check (id = auth.uid() or public.is_super_user());

drop policy if exists "only_super_delete" on public.members;
create policy "only_super_delete" on public.members
    as restrictive for delete to anon, authenticated
    using (public.is_super_user());

create or replace function public.member_directory()
returns table (id uuid, full_name text, avatar_path text, avatar_url text, pilot_rating text, country text)
language plpgsql
stable
security definer
set search_path = public
as $$
begin
    if not (public.is_active_member() or public.is_super_user()) then
        raise exception 'Active membership required' using errcode = '42501';
    end if;
    return query
        select m.id, m.full_name::text, m.avatar_path, m.avatar_url::text, m.pilot_rating::text, m.country::text
        from public.members m
        where m.membership_status = 'active'
        order by m.full_name;
end;
$$;

revoke all on function public.member_directory() from public;
grant execute on function public.member_directory() to authenticated;

-- 6. REVIEW RPC (Command Center) ----------------------------------------------

create or replace function public.review_membership(target_member_id uuid, new_status text, note text default null)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
    if not public.is_super_user() then
        raise exception 'Super user access required' using errcode = '42501';
    end if;
    if new_status not in ('pending', 'active', 'rejected', 'suspended') then
        raise exception 'Invalid status %', new_status;
    end if;
    update public.members
       set membership_status = new_status,
           reviewed_by = auth.uid(),
           reviewed_at = now(),
           review_note = nullif(trim(note), '')
     where id = target_member_id;
    if not found then
        raise exception 'Member not found';
    end if;
end;
$$;

revoke all on function public.review_membership(uuid, text, text) from public;
grant execute on function public.review_membership(uuid, text, text) to authenticated;

-- 7. CLUB FEATURES: ACTIVE MEMBERS ONLY ----------------------------------------

alter table public.member_flights enable row level security;

drop policy if exists "member_own_flights" on public.member_flights;
create policy "member_own_flights" on public.member_flights
    for all to authenticated
    using (member_id = auth.uid() or public.is_super_user())
    with check (member_id = auth.uid() or public.is_super_user());

drop policy if exists "only_active_own_flights" on public.member_flights;
create policy "only_active_own_flights" on public.member_flights
    as restrictive for all to anon, authenticated
    using ((member_id = auth.uid() and public.is_active_member()) or public.is_super_user())
    with check ((member_id = auth.uid() and public.is_active_member()) or public.is_super_user());

alter table public.direct_messages enable row level security;

drop policy if exists "member_dm_select" on public.direct_messages;
create policy "member_dm_select" on public.direct_messages
    for select to authenticated
    using (sender_id = auth.uid() or recipient_id = auth.uid());

drop policy if exists "member_dm_insert" on public.direct_messages;
create policy "member_dm_insert" on public.direct_messages
    for insert to authenticated
    with check (sender_id = auth.uid());

drop policy if exists "only_active_dm_select" on public.direct_messages;
create policy "only_active_dm_select" on public.direct_messages
    as restrictive for select to anon, authenticated
    using ((sender_id = auth.uid() or recipient_id = auth.uid()) and public.is_active_member());

drop policy if exists "only_active_dm_insert" on public.direct_messages;
create policy "only_active_dm_insert" on public.direct_messages
    as restrictive for insert to anon, authenticated
    with check (sender_id = auth.uid() and public.is_active_member());

drop policy if exists "no_dm_update" on public.direct_messages;
create policy "no_dm_update" on public.direct_messages
    as restrictive for update to anon, authenticated
    using (public.is_super_user());

drop policy if exists "no_dm_delete" on public.direct_messages;
create policy "no_dm_delete" on public.direct_messages
    as restrictive for delete to anon, authenticated
    using (public.is_super_user());

-- Site pass requests: only active members can submit.
drop policy if exists "only_own_or_super_insert" on public.site_pass_requests;
create policy "only_own_or_super_insert" on public.site_pass_requests
    as restrictive for insert to anon, authenticated
    with check ((member_id = auth.uid() and public.is_active_member()) or public.is_super_user());

-- 8. PRIVATE PROFILE PHOTO BUCKET ---------------------------------------------
-- Files live at member-photos/<user id>/<file>. Private: read through signed URLs.
-- Owner: read/write own folder. Active members + super users: read (directory).

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('member-photos', 'member-photos', false, 2097152, array['image/jpeg', 'image/png', 'image/webp'])
on conflict (id) do update set
    public = false,
    file_size_limit = excluded.file_size_limit,
    allowed_mime_types = excluded.allowed_mime_types;

drop policy if exists "member_photos_select" on storage.objects;
create policy "member_photos_select" on storage.objects
    for select to authenticated
    using (
        bucket_id = 'member-photos'
        and ((storage.foldername(name))[1] = auth.uid()::text or public.is_active_member() or public.is_super_user())
    );

drop policy if exists "member_photos_insert" on storage.objects;
create policy "member_photos_insert" on storage.objects
    for insert to authenticated
    with check (bucket_id = 'member-photos' and (storage.foldername(name))[1] = auth.uid()::text);

drop policy if exists "member_photos_update" on storage.objects;
create policy "member_photos_update" on storage.objects
    for update to authenticated
    using (bucket_id = 'member-photos' and (storage.foldername(name))[1] = auth.uid()::text)
    with check (bucket_id = 'member-photos' and (storage.foldername(name))[1] = auth.uid()::text);

drop policy if exists "member_photos_delete" on storage.objects;
create policy "member_photos_delete" on storage.objects
    for delete to authenticated
    using (
        bucket_id = 'member-photos'
        and ((storage.foldername(name))[1] = auth.uid()::text or public.is_super_user())
    );
