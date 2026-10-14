create table if not exists public.audit_log (
    id             bigint generated always as identity primary key,
    occurred_at    timestamptz not null default now(),
    actor_id       uuid,
    actor_email    text,
    action         text not null,
    table_name     text not null,
    record_id      text,
    record_label   text,
    changed_fields text[],
    old_data       jsonb,
    new_data       jsonb
);

create index if not exists audit_log_occurred_at_idx on public.audit_log (occurred_at desc);
create index if not exists audit_log_table_idx on public.audit_log (table_name, occurred_at desc);

alter table public.audit_log enable row level security;

drop policy if exists "super_users_read_audit" on public.audit_log;
create policy "super_users_read_audit" on public.audit_log
    for select to authenticated
    using (public.is_super_user());

-- No write policies: only the security-definer functions below can add entries.
revoke insert, update, delete, truncate on public.audit_log from anon, authenticated;

create or replace function public.csfa_audit_log_immutable()
returns trigger
language plpgsql
as $$
begin
    raise exception 'Audit log entries cannot be changed or deleted';
end;
$$;

drop trigger if exists csfa_audit_log_immutable on public.audit_log;
create trigger csfa_audit_log_immutable
    before update or delete on public.audit_log
    for each row execute function public.csfa_audit_log_immutable();

drop trigger if exists csfa_audit_log_no_truncate on public.audit_log;
create trigger csfa_audit_log_no_truncate
    before truncate on public.audit_log
    for each statement execute function public.csfa_audit_log_immutable();

-- 2. ROW TRIGGER -------------------------------------------------------------

create or replace function public.csfa_audit_row()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
    old_j   jsonb := case when tg_op <> 'INSERT' then to_jsonb(old) - 'track_points' end;
    new_j   jsonb := case when tg_op <> 'DELETE' then to_jsonb(new) - 'track_points' end;
    any_j   jsonb := coalesce(new_j, old_j);
    changed text[];
begin
    if tg_op = 'UPDATE' then
        select array_agg(n.key order by n.key) into changed
        from jsonb_each(new_j) n
        where n.value is distinct from old_j -> n.key
          and n.key not in ('updated_at');
        if changed is null then
            return null; -- nothing meaningful changed
        end if;
        old_j := (select jsonb_object_agg(k, old_j -> k) from unnest(changed) k);
        new_j := (select jsonb_object_agg(k, new_j -> k) from unnest(changed) k);
    end if;

    insert into public.audit_log (actor_id, actor_email, action, table_name, record_id, record_label, changed_fields, old_data, new_data)
    values (
        auth.uid(),
        auth.jwt() ->> 'email',
        lower(tg_op),
        tg_table_name,
        coalesce(any_j ->> 'id', any_j ->> 'user_id', any_j ->> 'key'),
        coalesce(any_j ->> 'full_name', any_j ->> 'pilot_name', any_j ->> 'name', any_j ->> 'email',
                 any_j ->> 'date_text', any_j ->> 'site_name', any_j ->> 'key'),
        changed,
        old_j,
        new_j
    );
    return null;
end;
$$;

do $$
declare
    t text;
begin
    foreach t in array array[
        'super_users', 'members', 'member_flights', 'site_pass_requests', 'site_pass_tiers',
        'booking_sessions', 'booking_locations', 'booking_addons', 'booking_config'
    ]
    loop
        execute format('drop trigger if exists csfa_audit on public.%I', t);
        execute format('create trigger csfa_audit after insert or update or delete on public.%I for each row execute function public.csfa_audit_row()', t);
    end loop;
end;
$$;

-- 3. COMMAND CENTER ACCESS EVENTS --------------------------------------------
-- Called by the Command Center after a sign-in attempt. The server decides whether it
-- was granted or denied, so a client can't log a fake success.

create or replace function public.log_command_center_signin()
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
    if auth.uid() is null then
        return;
    end if;
    insert into public.audit_log (actor_id, actor_email, action, table_name, record_id, record_label)
    values (
        auth.uid(),
        auth.jwt() ->> 'email',
        case when public.is_super_user() then 'signin' else 'signin_denied' end,
        'command_center',
        auth.uid()::text,
        auth.jwt() ->> 'email'
    );
end;
$$;

revoke all on function public.log_command_center_signin() from public;
grant execute on function public.log_command_center_signin() to authenticated;

-- 4. FEED FOR THE COMMAND CENTER ---------------------------------------------
-- App changes + Supabase Auth events, newest first, with filters and a time cursor.

create or replace function public.admin_audit_feed(
    p_limit    integer default 100,
    p_before   timestamptz default null,
    p_category text default null,
    p_search   text default null,
    p_from     date default null,
    p_to       date default null
)
returns table (
    occurred_at    timestamptz,
    source         text,
    actor_email    text,
    action         text,
    category       text,
    record_id      text,
    record_label   text,
    changed_fields text[],
    old_data       jsonb,
    new_data       jsonb,
    ip             text
)
language plpgsql
stable
security definer
set search_path = public
as $$
declare
    lim integer := least(greatest(coalesce(p_limit, 100), 1), 200);
    q   text := nullif(trim(coalesce(p_search, '')), '');
begin
    if not public.is_super_user() then
        raise exception 'Super user access required' using errcode = '42501';
    end if;

    return query
    select * from (
        select a.occurred_at as at, 'app'::text as src, a.actor_email as who, a.action as act, a.table_name as cat,
               a.record_id as rid, a.record_label as label, a.changed_fields as fields, a.old_data as before_data,
               a.new_data as after_data, null::text as ip_addr
        from public.audit_log a
        where (p_before is null or a.occurred_at < p_before)
          and (p_category is null or a.table_name = p_category)
          and (p_from is null or a.occurred_at >= p_from)
          and (p_to is null or a.occurred_at < p_to + 1)
          and (q is null or a.actor_email ilike '%' || q || '%' or a.record_label ilike '%' || q || '%'
               or a.record_id ilike '%' || q || '%' or a.action ilike '%' || q || '%')

        union all

        select e.created_at, 'auth'::text, e.payload ->> 'actor_username', e.payload ->> 'action', 'auth'::text,
               e.payload ->> 'actor_id', coalesce(e.payload -> 'traits' ->> 'user_email', e.payload ->> 'actor_username'),
               null::text[], null::jsonb, (e.payload -> 'traits')::jsonb, e.ip_address::text
        from auth.audit_log_entries e
        where (p_category is null or p_category = 'auth')
          and coalesce(e.payload ->> 'action', '') not in ('token_refreshed', 'token_revoked')
          and (p_before is null or e.created_at < p_before)
          and (p_from is null or e.created_at >= p_from)
          and (p_to is null or e.created_at < p_to + 1)
          and (q is null or e.payload ->> 'actor_username' ilike '%' || q || '%' or e.payload ->> 'action' ilike '%' || q || '%'
               or e.payload -> 'traits' ->> 'user_email' ilike '%' || q || '%')
    ) feed
    order by 1 desc
    limit lim;
end;
$$;

revoke all on function public.admin_audit_feed(integer, timestamptz, text, text, date, date) from public;
grant execute on function public.admin_audit_feed(integer, timestamptz, text, text, date, date) to authenticated;
