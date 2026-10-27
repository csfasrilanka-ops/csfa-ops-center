-- Membership IDs (CSFA-0001, CSFA-0002, ...) for Full Members.
-- Issued automatically the first time a member is active AND full. Temporary Members get none;
-- a Temporary Member moved to Full gets one at that moment. Once issued the number stays with
-- the member for good (suspension or a later change to Temporary keeps it) and is never reused.

-- 1. COLUMNS -------------------------------------------------------------------

create sequence if not exists public.members_member_no_seq as integer start with 1 minvalue 1;

alter table public.members
    add column if not exists member_no integer;

alter sequence public.members_member_no_seq owned by public.members.member_no;

alter table public.members drop constraint if exists members_member_no_key;
alter table public.members add constraint members_member_no_key unique (member_no);

-- Display form. Pads to 4 digits and keeps growing past 9999 instead of truncating.
alter table public.members
    add column if not exists member_id text
    generated always as (
        case when member_no is null then null
             else 'CSFA-' || lpad(member_no::text, greatest(4, length(member_no::text)), '0')
        end
    ) stored;

-- 2. BACKFILL EXISTING FULL MEMBERS --------------------------------------------
-- Numbered in the order they were approved (falling back to when they applied).

with ordered as (
    select id,
           (select coalesce(max(member_no), 0) from public.members)
             + row_number() over (order by coalesce(reviewed_at, applied_at), applied_at, id) as n
    from public.members
    where membership_status = 'active'
      and membership_type = 'full'
      and member_no is null
)
update public.members m
   set member_no = o.n
  from ordered o
 where o.id = m.id;

select setval(
    'public.members_member_no_seq',
    coalesce((select max(member_no) from public.members), 0) + 1,
    false
);

-- 3. ISSUE ON APPROVAL / UPGRADE -----------------------------------------------
-- Named to sort after the csfa_guard_* triggers so it sees the final status and type.

create or replace function public.csfa_issue_member_no()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
    if new.member_no is null
       and new.membership_status = 'active'
       and new.membership_type = 'full' then
        new.member_no := nextval('public.members_member_no_seq');
    end if;
    return new;
end;
$$;

drop trigger if exists csfa_issue_member_no on public.members;
create trigger csfa_issue_member_no
    before insert or update of membership_status, membership_type, member_no on public.members
    for each row execute function public.csfa_issue_member_no();

-- 4. MEMBERS CAN'T CHANGE THEIR OWN NUMBER -------------------------------------

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
        new.member_no := null;
        new.reviewed_by := null;
        new.reviewed_at := null;
        new.review_note := null;
        new.applied_at := now();
    else
        new.id := old.id;
        new.email := old.email;
        new.membership_status := old.membership_status;
        new.membership_type := old.membership_type;
        new.member_no := old.member_no;
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
