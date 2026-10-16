alter table public.members
    add column if not exists membership_type text not null default 'full';

update public.members set membership_type = 'full' where membership_type is distinct from 'full';

alter table public.members drop constraint if exists members_membership_type_check;
alter table public.members add constraint members_membership_type_check
    check (membership_type in ('full', 'temporary'));

-- 2. MEMBERS CAN'T CHANGE THEIR OWN TYPE ---------------------------------------

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
        new.membership_type := 'full';
        new.reviewed_by := null;
        new.reviewed_at := null;
        new.review_note := null;
        new.applied_at := now();
    else
        new.id := old.id;
        new.email := old.email;
        new.membership_status := old.membership_status;
        new.membership_type := old.membership_type;
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

-- 3. SUPER USERS MUST STAY FULL MEMBERS ----------------------------------------

create or replace function public.csfa_guard_super_user_membership_type()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
    if new.membership_type <> 'full'
       and exists (select 1 from public.super_users where user_id = new.id) then
        raise exception 'This account is a super user. Super users must be Full Members. Revoke super user access first.';
    end if;
    return new;
end;
$$;

drop trigger if exists csfa_guard_super_user_membership_type on public.members;
create trigger csfa_guard_super_user_membership_type
    before insert or update of membership_type on public.members
    for each row execute function public.csfa_guard_super_user_membership_type();

-- 4. CHANGE TYPE RPC (Command Center) ------------------------------------------

create or replace function public.set_membership_type(target_member_id uuid, new_type text)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
    if not public.is_super_user() then
        raise exception 'Super user access required' using errcode = '42501';
    end if;
    if new_type not in ('full', 'temporary') then
        raise exception 'Invalid membership type %', new_type;
    end if;
    update public.members set membership_type = new_type where id = target_member_id;
    if not found then
        raise exception 'Member not found';
    end if;
end;
$$;

revoke all on function public.set_membership_type(uuid, text) from public;
grant execute on function public.set_membership_type(uuid, text) to authenticated;

-- 5. GRANT SUPER USER: FULL MEMBERS ONLY ---------------------------------------

create or replace function public.grant_super_user(target_email text)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
    target_id uuid;
    target_type text;
begin
    if not public.is_super_user() then
        raise exception 'Super user access required' using errcode = '42501';
    end if;
    select id into target_id from auth.users where lower(email) = lower(trim(target_email));
    if target_id is null then
        raise exception 'No account found for %', target_email;
    end if;
    if exists (select 1 from public.super_users where user_id = target_id) then
        return;
    end if;
    select membership_type into target_type from public.members where id = target_id;
    if target_type is null then
        raise exception '% has no club membership. Only Full Members can be super users.', target_email;
    end if;
    if target_type <> 'full' then
        raise exception '% is a Temporary Member. Change them to a Full Member first.', target_email;
    end if;
    insert into public.super_users (user_id, email, granted_by)
    values (target_id, lower(trim(target_email)), auth.uid())
    on conflict (user_id) do nothing;
end;
$$;

-- 6. USER LIST: INCLUDE MEMBERSHIP TYPE ----------------------------------------
-- Return type changes, so the function has to be dropped and recreated.

drop function if exists public.admin_list_users();

create function public.admin_list_users()
returns table (user_id uuid, email text, full_name text, is_super boolean, membership_type text, created_at timestamptz)
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
               m.membership_type,
               u.created_at
        from auth.users u
        left join public.members m on m.id = u.id
        left join public.super_users s on s.user_id = u.id
        order by (s.user_id is not null) desc, u.email;
end;
$$;

revoke all on function public.admin_list_users() from public;
grant execute on function public.admin_list_users() to authenticated;
