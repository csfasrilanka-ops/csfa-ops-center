create table if not exists public.gallery_albums (
    id             uuid primary key default gen_random_uuid(),
    title          text not null check (char_length(title) between 1 and 120),
    description    text check (description is null or char_length(description) <= 1000),
    sort_order     integer not null default 0,
    is_published   boolean not null default true,
    cover_photo_id uuid,
    created_at     timestamptz not null default now(),
    updated_at     timestamptz
);

create table if not exists public.gallery_photos (
    id           uuid primary key default gen_random_uuid(),
    album_id     uuid not null references public.gallery_albums (id) on delete cascade,
    path         text not null,
    thumb_path   text not null,
    caption      text check (caption is null or char_length(caption) <= 300),
    width        integer,
    height       integer,
    sort_order   integer not null default 0,
    is_published boolean not null default true,
    created_at   timestamptz not null default now(),
    constraint gallery_photos_paths_in_album check (path like album_id::text || '/%' and thumb_path like album_id::text || '/%')
);

alter table public.gallery_albums drop constraint if exists gallery_albums_cover_photo_fk;
alter table public.gallery_albums add constraint gallery_albums_cover_photo_fk
    foreign key (cover_photo_id) references public.gallery_photos (id) on delete set null;

create index if not exists gallery_albums_order_idx on public.gallery_albums (sort_order, created_at);
create index if not exists gallery_photos_album_order_idx on public.gallery_photos (album_id, sort_order, created_at);

-- 2. ACCESS RULES ----------------------------------------------------------------

alter table public.gallery_albums enable row level security;
alter table public.gallery_photos enable row level security;

drop policy if exists "public_read_published" on public.gallery_albums;
create policy "public_read_published" on public.gallery_albums
    for select to anon, authenticated
    using (is_published or public.is_super_user());

drop policy if exists "public_read_published" on public.gallery_photos;
create policy "public_read_published" on public.gallery_photos
    for select to anon, authenticated
    using (
        public.is_super_user()
        or (is_published and exists (select 1 from public.gallery_albums a where a.id = album_id and a.is_published))
    );

do $$
declare
    t text;
begin
    foreach t in array array['gallery_albums', 'gallery_photos']
    loop
        execute format('drop policy if exists "super_user_write" on public.%I', t);
        execute format('create policy "super_user_write" on public.%I for all to authenticated using (public.is_super_user()) with check (public.is_super_user())', t);

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

-- 3. STORAGE: public gallery bucket, super-user uploads only -------------------------

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('gallery', 'gallery', true, 5242880, array['image/webp', 'image/jpeg', 'image/png'])
on conflict (id) do update set
    public = true,
    file_size_limit = excluded.file_size_limit,
    allowed_mime_types = excluded.allowed_mime_types;

drop policy if exists "gallery_super_insert" on storage.objects;
create policy "gallery_super_insert" on storage.objects
    for insert to authenticated
    with check (bucket_id = 'gallery' and public.is_super_user());

drop policy if exists "gallery_super_update" on storage.objects;
create policy "gallery_super_update" on storage.objects
    for update to authenticated
    using (bucket_id = 'gallery' and public.is_super_user())
    with check (bucket_id = 'gallery' and public.is_super_user());

drop policy if exists "gallery_super_delete" on storage.objects;
create policy "gallery_super_delete" on storage.objects
    for delete to authenticated
    using (bucket_id = 'gallery' and public.is_super_user());

drop policy if exists "gallery_super_select" on storage.objects;
create policy "gallery_super_select" on storage.objects
    for select to authenticated
    using (bucket_id = 'gallery' and public.is_super_user());

-- 4. AUDIT LABELS: show album titles / photo captions in the audit log -----------

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
        coalesce(any_j ->> 'full_name', any_j ->> 'pilot_name', any_j ->> 'name', any_j ->> 'title', any_j ->> 'email',
                 any_j ->> 'date_text', any_j ->> 'site_name', any_j ->> 'caption', any_j ->> 'path', any_j ->> 'key'),
        changed,
        old_j,
        new_j
    );
    return null;
end;
$$;
