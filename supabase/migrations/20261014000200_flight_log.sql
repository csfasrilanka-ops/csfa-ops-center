alter table public.member_flights
    add column if not exists landing_site     text,
    add column if not exists launch_time      time,
    add column if not exists landing_time     time,
    add column if not exists flight_type      text,
    add column if not exists glider           text,
    add column if not exists wind_direction   text,
    add column if not exists wind_speed_kmh   integer,
    add column if not exists conditions       text,
    add column if not exists altitude_gain_m  integer,
    add column if not exists max_climb_ms     numeric(4, 1),
    add column if not exists track_length_km  numeric(7, 2),
    add column if not exists distance_km      numeric(7, 2),
    add column if not exists launch_lat       double precision,
    add column if not exists launch_lon       double precision,
    add column if not exists landing_lat      double precision,
    add column if not exists landing_lon      double precision,
    add column if not exists incident         boolean not null default false,
    add column if not exists incident_notes   text,
    add column if not exists track_path       text,
    add column if not exists track_points     jsonb,
    add column if not exists created_at       timestamptz not null default now(),
    add column if not exists updated_at       timestamptz;

alter table public.member_flights drop constraint if exists member_flights_flight_type_check;
alter table public.member_flights add constraint member_flights_flight_type_check
    check (flight_type is null or flight_type in ('Solo', 'Tandem Pilot', 'Tandem Passenger', 'Training', 'Hike & Fly', 'Tow', 'Competition'));

alter table public.member_flights drop constraint if exists member_flights_sane_values_check;
alter table public.member_flights add constraint member_flights_sane_values_check
    check (
        (airtime_minutes is null or airtime_minutes between 0 and 1440)
        and (wind_speed_kmh is null or wind_speed_kmh between 0 and 150)
        and (max_climb_ms is null or max_climb_ms between -30 and 30)
        and (track_points is null or jsonb_typeof(track_points) = 'array' and jsonb_array_length(track_points) <= 1000)
    ) not valid;

-- Track files must sit in the member's own folder.
alter table public.member_flights drop constraint if exists member_flights_track_path_check;
alter table public.member_flights add constraint member_flights_track_path_check
    check (track_path is null or track_path like member_id::text || '/%') not valid;

create index if not exists member_flights_member_date_idx on public.member_flights (member_id, flight_date desc);

-- 2. PRIVATE TRACK FILE BUCKET (IGC / GPX) ------------------------------------
-- Files at flight-tracks/<user id>/<file>. Owner reads/writes own folder; super users read.

insert into storage.buckets (id, name, public, file_size_limit)
values ('flight-tracks', 'flight-tracks', false, 5242880)
on conflict (id) do update set public = false, file_size_limit = excluded.file_size_limit;

drop policy if exists "flight_tracks_select" on storage.objects;
create policy "flight_tracks_select" on storage.objects
    for select to authenticated
    using (
        bucket_id = 'flight-tracks'
        and ((storage.foldername(name))[1] = auth.uid()::text or public.is_super_user())
    );

drop policy if exists "flight_tracks_insert" on storage.objects;
create policy "flight_tracks_insert" on storage.objects
    for insert to authenticated
    with check (
        bucket_id = 'flight-tracks'
        and (storage.foldername(name))[1] = auth.uid()::text
        and public.is_active_member()
    );

drop policy if exists "flight_tracks_delete" on storage.objects;
create policy "flight_tracks_delete" on storage.objects
    for delete to authenticated
    using (
        bucket_id = 'flight-tracks'
        and ((storage.foldername(name))[1] = auth.uid()::text or public.is_super_user())
    );
