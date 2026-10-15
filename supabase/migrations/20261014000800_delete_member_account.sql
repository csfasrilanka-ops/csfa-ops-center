create or replace function public.delete_member_account(target_user_id uuid)
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
        raise exception 'You cannot remove your own account';
    end if;
    if exists (select 1 from public.super_users where user_id = target_user_id) then
        raise exception 'This account is a super user. Revoke super user access first.';
    end if;
    if not exists (select 1 from auth.users where id = target_user_id) then
        raise exception 'Account not found';
    end if;

    delete from public.direct_messages where sender_id = target_user_id or recipient_id = target_user_id;
    delete from public.member_flights where member_id = target_user_id;
    delete from public.site_pass_requests where member_id = target_user_id;
    delete from public.members where id = target_user_id;
    delete from auth.users where id = target_user_id;
end;
$$;

revoke all on function public.delete_member_account(uuid) from public;
grant execute on function public.delete_member_account(uuid) to authenticated;
