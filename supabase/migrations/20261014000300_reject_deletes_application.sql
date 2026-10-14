create or replace function public.reject_and_delete_application(target_member_id uuid)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
    target_status text;
begin
    if not public.is_super_user() then
        raise exception 'Super user access required' using errcode = '42501';
    end if;
    if target_member_id = auth.uid() then
        raise exception 'You cannot reject your own account';
    end if;
    if exists (select 1 from public.super_users where user_id = target_member_id) then
        raise exception 'This account is a super user. Revoke super user access first.';
    end if;

    select membership_status into target_status from public.members where id = target_member_id;
    if target_status is null then
        raise exception 'Application not found';
    end if;
    if target_status <> 'pending' then
        raise exception 'Only pending applications can be rejected. Use Suspend for existing members.';
    end if;

    -- Anything the account created (normally nothing for a pending applicant).
    delete from public.direct_messages where sender_id = target_member_id or recipient_id = target_member_id;
    delete from public.member_flights where member_id = target_member_id;
    delete from public.site_pass_requests where member_id = target_member_id;
    delete from public.members where id = target_member_id;
    delete from auth.users where id = target_member_id;
end;
$$;

revoke all on function public.reject_and_delete_application(uuid) from public;
grant execute on function public.reject_and_delete_application(uuid) to authenticated;
