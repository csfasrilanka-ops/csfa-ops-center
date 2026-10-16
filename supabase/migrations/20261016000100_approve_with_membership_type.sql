-- Approving an application also sets its membership type (chosen in the Command Center),
-- in one step so a member is never active with an unchosen type.

create or replace function public.approve_membership(target_member_id uuid, new_type text)
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
    update public.members
       set membership_status = 'active',
           membership_type = new_type,
           reviewed_by = auth.uid(),
           reviewed_at = now(),
           review_note = null
     where id = target_member_id;
    if not found then
        raise exception 'Member not found';
    end if;
end;
$$;

revoke all on function public.approve_membership(uuid, text) from public;
grant execute on function public.approve_membership(uuid, text) to authenticated;
