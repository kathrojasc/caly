-- Caly · esquema de base de datos (Supabase / PostgreSQL)
-- Pegar completo en Supabase → SQL Editor → Run. Se puede ejecutar una sola vez.
-- Las reglas de reservas viven aquí, en el servidor: ninguna pantalla puede saltárselas.

create schema if not exists extensions;
create extension if not exists btree_gist with schema extensions;

-- ============================================================
-- Tablas
-- ============================================================
create table public.businesses (
  id              uuid primary key default gen_random_uuid(),
  name            text not null,
  slug            text not null unique check (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$'),
  plan            text not null default 'Prueba' check (plan in ('Prueba','Pro')),
  enabled         boolean not null default true,
  trial_ends_at   timestamptz default (now() + interval '14 days'),
  last_paid_at    date,
  next_pay_at     date,
  track_payments  boolean not null default false,
  show_staff      boolean not null default false,
  config          jsonb not null default '{"slotMinutes":45,"bufferMinutes":0,"minNoticeHours":2,"windowDays":21,"cancelNoticeHours":12}',
  brand           jsonb not null default '{}',
  business_hours  jsonb not null default '{}',   -- {"1":[{"start":"09:00","end":"19:00"}]}  (0 = domingo)
  created_at      timestamptz not null default now()
);

create table public.profiles (
  user_id      uuid primary key references auth.users(id) on delete cascade,
  role         text not null check (role in ('super','admin','client')),
  business_id  uuid references public.businesses(id),
  must_change  boolean not null default false,
  check ((role = 'super' and business_id is null) or (role <> 'super' and business_id is not null))
);

create table public.staff (
  id           uuid primary key default gen_random_uuid(),
  business_id  uuid not null references public.businesses(id),
  name         text not null,
  schedule     jsonb not null default '{}',      -- {"1":[{"start":"09:00","end":"13:00"}]}
  time_off     jsonb not null default '[]',      -- [{"id":"..","from":"2026-12-01","to":"2026-12-05","note":".."}]
  deleted_at   timestamptz
);

create table public.services (
  id           uuid primary key default gen_random_uuid(),
  business_id  uuid not null references public.businesses(id),
  name         text not null,
  minutes      int  not null check (minutes between 5 and 480),
  paused       boolean not null default false,
  staff_ids    uuid[] not null default '{}',
  deleted_at   timestamptz
);

create table public.closures (
  id           uuid primary key default gen_random_uuid(),
  business_id  uuid not null references public.businesses(id),
  from_date    date not null,
  to_date      date,
  note         text not null default '',
  repeat       text not null default 'none' check (repeat in ('none','weekly')),
  start_time   time,
  end_time     time,
  check ((start_time is null) = (end_time is null))
);

create table public.clients (
  id           uuid primary key default gen_random_uuid(),
  business_id  uuid not null references public.businesses(id),
  user_id      uuid references auth.users(id),
  doc_type     text not null default 'DNI',
  doc          text not null,
  nombres      text not null,
  apellidos    text not null,
  phone        text not null default '',
  created_by   text not null default 'client',
  unique (business_id, doc),
  unique (business_id, user_id)
);

create table public.appointments (
  id            uuid primary key default gen_random_uuid(),
  business_id   uuid not null references public.businesses(id),
  client_id     uuid not null references public.clients(id),
  staff_id      uuid not null references public.staff(id),
  service_id    uuid references public.services(id),
  date          date not null,
  start_time    time not null,
  end_time      time not null,
  status        text not null default 'CONFIRMED' check (status in ('CONFIRMED','CANCELLED')),
  paid          boolean not null default false,
  cancelled_by  text check (cancelled_by in ('client','admin')),
  cancelled_at  timestamptz,
  created_by    text not null default 'client',
  created_at    timestamptz not null default now(),
  span          tsrange generated always as (tsrange(date + start_time, date + end_time, '[)')) stored,
  check (end_time > start_time),
  -- La garantía real: un trabajador no puede tener dos citas confirmadas que se crucen.
  constraint no_overlap exclude using gist (staff_id with =, span with &&) where (status = 'CONFIRMED')
);
create index on public.appointments (business_id, date);

create table public.audit_log (
  id           bigint generated always as identity primary key,
  business_id  uuid references public.businesses(id),
  ts           timestamptz not null default now(),
  role         text not null,                  -- client | admin | super | system
  actor_id     uuid,
  action       text not null,
  text         text not null,
  appt_id      uuid,
  doc          text,
  data         jsonb
);
create index on public.audit_log (business_id, ts desc);

-- ============================================================
-- Funciones de apoyo
-- ============================================================
create function public.my_role() returns text language sql stable security definer set search_path = public as
$$ select role from profiles where user_id = auth.uid() $$;

create function public.my_biz() returns uuid language sql stable security definer set search_path = public as
$$ select business_id from profiles where user_id = auth.uid() $$;

create function public.lima_now() returns timestamp language sql stable as
$$ select now() at time zone 'America/Lima' $$;

-- Estado de la cuenta: ok | disabled | trial_ended | unpaid  (3 días de gracia tras el vencimiento)
create function public.biz_status(b uuid) returns text language sql stable security definer set search_path = public as
$$ select case
     when not enabled then 'disabled'
     when plan = 'Prueba' and trial_ends_at is not null and trial_ends_at < now() then 'trial_ended'
     when plan = 'Pro' and next_pay_at is not null and next_pay_at + 3 < lima_now()::date then 'unpaid'
     else 'ok' end
   from businesses where id = b $$;

create function public.biz_ok(b uuid) returns boolean language sql stable security definer set search_path = public as
$$ select coalesce(biz_status(b) = 'ok', false) $$;

-- ¿Algún tramo del arreglo [{"start","end"}] cubre todo el rango pedido?
create function public.covers(ranges jsonb, s time, e time) returns boolean language sql immutable as
$$ select coalesce(bool_or((r->>'start')::time <= s and (r->>'end')::time >= e), false)
   from jsonb_array_elements(coalesce(ranges, '[]'::jsonb)) r $$;

-- Reglas de una cita: horario del negocio, cierres, horario y ausencias del trabajador, servicio.
create function public.check_slot(b uuid, p_staff uuid, p_service uuid, d date, s time, e time) returns void
language plpgsql stable security definer set search_path = public as $$
declare dow text := extract(dow from d)::text; biz businesses; st staff; sv services; c closures;
begin
  select * into biz from businesses where id = b;
  if not public.covers(biz.business_hours -> dow, s, e) then raise exception 'fuera_horario_negocio'; end if;
  for c in select * from closures where business_id = b loop
    if (case when c.repeat = 'weekly'
             then d >= c.from_date and (c.to_date is null or d <= c.to_date) and extract(dow from d) = extract(dow from c.from_date)
             else d between c.from_date and coalesce(c.to_date, c.from_date) end)
       and (c.start_time is null or (s < c.end_time and c.start_time < e)) then
      raise exception 'negocio_cerrado';
    end if;
  end loop;
  select * into st from staff where id = p_staff and business_id = b and deleted_at is null;
  if not found then raise exception 'trabajador_no_disponible'; end if;
  if exists (select 1 from jsonb_array_elements(st.time_off) o where d between (o->>'from')::date and (o->>'to')::date) then
    raise exception 'trabajador_ausente';
  end if;
  if not public.covers(st.schedule -> dow, s, e) then raise exception 'fuera_horario_trabajador'; end if;
  if p_service is not null then
    select * into sv from services where id = p_service and business_id = b and deleted_at is null;
    if not found or not (p_staff = any (sv.staff_ids)) then raise exception 'servicio_no_disponible'; end if;
  end if;
end $$;

create function public.appt_before_insert() returns trigger language plpgsql security definer set search_path = public as $$
begin
  perform public.check_slot(new.business_id, new.staff_id, new.service_id, new.date, new.start_time, new.end_time);
  return new;
end $$;
create trigger appt_rules before insert on public.appointments for each row execute function public.appt_before_insert();

-- ============================================================
-- Registro de actividad (solo anexar)
-- ============================================================
create function public.audit_actor_role() returns text language sql stable security definer set search_path = public as
$$ select coalesce(my_role(), case when auth.uid() is null then 'system' else 'client' end) $$;

create function public.audit_appt() returns trigger language plpgsql security definer set search_path = public as $$
declare c clients; act text; txt text; who text;
begin
  select * into c from clients where id = new.client_id;
  who := c.nombres || ' ' || c.apellidos;
  if tg_op = 'INSERT' then
    act := 'appt.create'; txt := format('Se creó la cita del %s a las %s para %s.', new.date, to_char(new.start_time,'HH24:MI'), who);
  elsif new.status = 'CANCELLED' and old.status = 'CONFIRMED' then
    act := 'appt.cancel'; txt := format('Se canceló la cita del %s a las %s de %s (por %s).', new.date, to_char(new.start_time,'HH24:MI'), who, coalesce(new.cancelled_by, '—'));
  elsif new.paid is distinct from old.paid then
    act := 'appt.paid'; txt := format('Pago de %s (%s): %s.', who, new.date, case when new.paid then 'pagado' else 'pendiente' end);
  else return new; end if;
  insert into audit_log (business_id, role, actor_id, action, text, appt_id, doc)
  values (new.business_id, audit_actor_role(), auth.uid(), act, txt, new.id, c.doc);
  return new;
end $$;
create trigger audit_appt after insert or update on public.appointments for each row execute function public.audit_appt();

create function public.audit_generic() returns trigger language plpgsql security definer set search_path = public as $$
declare r record; b uuid; label text;
begin
  r := case when tg_op = 'DELETE' then old else new end;
  b := case when tg_table_name = 'businesses' then (to_jsonb(r)->>'id')::uuid else (to_jsonb(r)->>'business_id')::uuid end;
  label := case tg_table_name when 'businesses' then 'del negocio' when 'staff' then 'del trabajador' when 'services' then 'del servicio'
                              when 'closures' then 'de un cierre' else 'de un cliente' end;
  insert into audit_log (business_id, role, actor_id, action, text, data)
  values (b, audit_actor_role(), auth.uid(), tg_table_name || '.' || lower(tg_op),
          case tg_op when 'INSERT' then 'Se creó el registro ' when 'UPDATE' then 'Se modificó el registro ' else 'Se eliminó el registro ' end || label || '.',
          jsonb_build_object('antes', case when tg_op <> 'INSERT' then to_jsonb(old) end, 'despues', case when tg_op <> 'DELETE' then to_jsonb(new) end));
  return r;
end $$;
create trigger audit_businesses after insert or update or delete on public.businesses for each row execute function public.audit_generic();
create trigger audit_staff      after insert or update or delete on public.staff      for each row execute function public.audit_generic();
create trigger audit_services   after insert or update or delete on public.services   for each row execute function public.audit_generic();
create trigger audit_closures   after insert or update or delete on public.closures   for each row execute function public.audit_generic();
create trigger audit_clients    after insert or update or delete on public.clients    for each row execute function public.audit_generic();

create function public.audit_immutable() returns trigger language plpgsql as
$$ begin raise exception 'El registro de actividad no se puede modificar'; end $$;
create trigger audit_log_immutable before update or delete on public.audit_log for each row execute function public.audit_immutable();

-- ============================================================
-- Protección de columnas sensibles
-- ============================================================
create function public.protect_business() returns trigger language plpgsql as $$
begin
  if coalesce(public.my_role(), 'system') not in ('super', 'system') and (
       new.plan is distinct from old.plan or new.enabled is distinct from old.enabled
    or new.trial_ends_at is distinct from old.trial_ends_at or new.last_paid_at is distinct from old.last_paid_at
    or new.next_pay_at is distinct from old.next_pay_at or new.slug is distinct from old.slug) then
    raise exception 'Solo el superadmin puede cambiar plan, cobro, estado o enlace';
  end if;
  return new;
end $$;
create trigger protect_business before update on public.businesses for each row execute function public.protect_business();

create function public.protect_profile() returns trigger language plpgsql as $$
begin
  if coalesce(public.my_role(), 'system') not in ('super', 'system')
     and (new.role is distinct from old.role or new.business_id is distinct from old.business_id) then
    raise exception 'No puedes cambiar tu rol';
  end if;
  return new;
end $$;
create trigger protect_profile before update on public.profiles for each row execute function public.protect_profile();

-- ============================================================
-- Seguridad por filas (RLS)
-- ============================================================
alter table public.businesses   enable row level security;
alter table public.profiles     enable row level security;
alter table public.staff        enable row level security;
alter table public.services     enable row level security;
alter table public.closures     enable row level security;
alter table public.clients      enable row level security;
alter table public.appointments enable row level security;
alter table public.audit_log    enable row level security;

create policy biz_super   on public.businesses for all    to authenticated using (my_role() = 'super') with check (my_role() = 'super');
create policy biz_admin_r on public.businesses for select to authenticated using (id = my_biz());
create policy biz_admin_u on public.businesses for update to authenticated using (my_role() = 'admin' and id = my_biz() and biz_ok(id)) with check (id = my_biz());

create policy prof_self   on public.profiles for select to authenticated using (user_id = auth.uid() or my_role() = 'super');
create policy prof_upd    on public.profiles for update to authenticated using (user_id = auth.uid() or my_role() = 'super');

create policy staff_super    on public.staff for all to authenticated using (my_role() = 'super') with check (my_role() = 'super');
create policy staff_admin    on public.staff for all to authenticated using (my_role() = 'admin' and business_id = my_biz() and biz_ok(business_id)) with check (business_id = my_biz());
create policy svc_super      on public.services for all to authenticated using (my_role() = 'super') with check (my_role() = 'super');
create policy svc_admin      on public.services for all to authenticated using (my_role() = 'admin' and business_id = my_biz() and biz_ok(business_id)) with check (business_id = my_biz());
create policy clo_super      on public.closures for all to authenticated using (my_role() = 'super') with check (my_role() = 'super');
create policy clo_admin      on public.closures for all to authenticated using (my_role() = 'admin' and business_id = my_biz() and biz_ok(business_id)) with check (business_id = my_biz());
create policy cli_super      on public.clients for all to authenticated using (my_role() = 'super') with check (my_role() = 'super');
create policy cli_admin      on public.clients for all to authenticated using (my_role() = 'admin' and business_id = my_biz() and biz_ok(business_id)) with check (business_id = my_biz());
create policy cli_self       on public.clients for select to authenticated using (user_id = auth.uid());
create policy appt_super     on public.appointments for select to authenticated using (my_role() = 'super');
create policy appt_admin     on public.appointments for all to authenticated using (my_role() = 'admin' and business_id = my_biz() and biz_ok(business_id)) with check (business_id = my_biz());
create policy appt_client    on public.appointments for select to authenticated using (client_id in (select id from clients where user_id = auth.uid()));
create policy audit_super    on public.audit_log for select to authenticated using (my_role() = 'super');

-- ============================================================
-- Permisos (las tablas no se exponen solas)
-- ============================================================
grant usage on schema public to anon, authenticated;
grant select, insert, update, delete on public.businesses, public.staff, public.services, public.closures to authenticated;
grant select, insert, update on public.clients, public.appointments to authenticated;
grant select, update on public.profiles to authenticated;
grant select on public.audit_log to authenticated;
revoke all on public.audit_log from anon;

-- ============================================================
-- Funciones públicas para reservar
-- ============================================================
-- Datos públicos de un negocio por su enlace (sin datos de clientes)
create function public.public_business(p_slug text) returns jsonb language plpgsql stable security definer set search_path = public as $$
declare b businesses; st text;
begin
  select * into b from businesses where slug = p_slug;
  if not found then return null; end if;
  st := biz_status(b.id);
  if st <> 'ok' then return jsonb_build_object('name', b.name, 'brand', b.brand, 'status', 'unavailable'); end if;
  return jsonb_build_object(
    'id', b.id, 'name', b.name, 'slug', b.slug, 'status', 'ok', 'plan', b.plan, 'brand', b.brand,
    'config', b.config, 'business_hours', b.business_hours, 'show_staff', b.show_staff,
    'staff',    (select coalesce(jsonb_agg(jsonb_build_object('id', id, 'name', name, 'schedule', schedule, 'time_off', time_off) order by name), '[]') from staff where business_id = b.id and deleted_at is null),
    'services', (select coalesce(jsonb_agg(jsonb_build_object('id', id, 'name', name, 'minutes', minutes, 'staff_ids', staff_ids) order by name), '[]') from services where business_id = b.id and deleted_at is null and not paused),
    'closures', (select coalesce(jsonb_agg(jsonb_build_object('from', from_date, 'to', to_date, 'repeat', repeat, 'start', start_time, 'end', end_time)), '[]') from closures where business_id = b.id));
end $$;

-- Horas ocupadas (sin nombres) para calcular la disponibilidad
create function public.public_busy(p_slug text, p_from date, p_to date)
returns table (staff_id uuid, date date, start_time time, end_time time) language sql stable security definer set search_path = public as $$
  select a.staff_id, a.date, a.start_time, a.end_time from appointments a join businesses b on b.id = a.business_id
  where b.slug = p_slug and biz_ok(b.id) and a.status = 'CONFIRMED' and a.date between p_from and least(p_to, p_from + 62) $$;

-- Cliente que ya inició sesión: vincula o crea su ficha en ese negocio
create function public.register_client(p_slug text, p_doc_type text, p_doc text, p_nombres text, p_apellidos text, p_phone text) returns uuid
language plpgsql security definer set search_path = public as $$
declare b businesses; c clients;
begin
  if auth.uid() is null then raise exception 'sin_sesion'; end if;
  select * into b from businesses where slug = p_slug;
  if not found or not biz_ok(b.id) then raise exception 'negocio_no_disponible'; end if;
  select * into c from clients where business_id = b.id and doc = p_doc;
  if found then
    if c.user_id is not null and c.user_id <> auth.uid() then raise exception 'documento_ya_registrado'; end if;
    update clients set user_id = auth.uid(), doc_type = p_doc_type, nombres = p_nombres, apellidos = p_apellidos, phone = p_phone where id = c.id;
    return c.id;
  end if;
  insert into clients (business_id, user_id, doc_type, doc, nombres, apellidos, phone, created_by)
  values (b.id, auth.uid(), p_doc_type, p_doc, p_nombres, p_apellidos, p_phone, 'client') returning id into c.id;
  return c.id;
end $$;

-- Reservar como cliente: valida anticipación y ventana, asigna trabajador en turno rotativo
create function public.book_appointment(p_slug text, p_service uuid, p_staff uuid, p_date date, p_start time) returns uuid
language plpgsql security definer set search_path = public as $$
declare b businesses; c clients; mins int; e time; cand uuid; new_id uuid; cfg jsonb; ts timestamp; chosen uuid;
begin
  if auth.uid() is null then raise exception 'sin_sesion'; end if;
  select * into b from businesses where slug = p_slug;
  if not found or not biz_ok(b.id) then raise exception 'negocio_no_disponible'; end if;
  select * into c from clients where business_id = b.id and user_id = auth.uid();
  if not found then raise exception 'cliente_sin_ficha'; end if;
  cfg := b.config;
  if p_service is not null then
    select minutes into mins from services where id = p_service and business_id = b.id and not paused and deleted_at is null;
    if mins is null then raise exception 'servicio_no_disponible'; end if;
  else mins := (cfg->>'slotMinutes')::int; end if;
  e := p_start + make_interval(mins => mins);
  if e <= p_start then raise exception 'fuera_horario_negocio'; end if;
  ts := p_date + p_start;
  if ts < lima_now() + make_interval(hours => (cfg->>'minNoticeHours')::int) then raise exception 'sin_anticipacion'; end if;
  if p_date > lima_now()::date + (cfg->>'windowDays')::int then raise exception 'fuera_de_ventana'; end if;
  for cand in
    select s.id from staff s
    where s.business_id = b.id and s.deleted_at is null and (p_staff is null or s.id = p_staff)
      and (p_service is null or s.id = any (coalesce((select sv.staff_ids from services sv where sv.id = p_service), '{}')))
    order by (select max(created_at) from appointments a where a.staff_id = s.id) nulls first, s.name
  loop
    begin
      perform check_slot(b.id, cand, p_service, p_date, p_start, e);
      if exists (select 1 from appointments a where a.staff_id = cand and a.status = 'CONFIRMED' and a.date = p_date and a.start_time < e and p_start < a.end_time) then continue; end if;
      chosen := cand; exit;
    exception when raise_exception then continue;
    end;
  end loop;
  if chosen is null then raise exception 'horario_ocupado'; end if;
  begin
    insert into appointments (business_id, client_id, staff_id, service_id, date, start_time, end_time, created_by)
    values (b.id, c.id, chosen, p_service, p_date, p_start, e, 'client') returning id into new_id;
  exception when exclusion_violation then raise exception 'horario_ocupado';
  end;
  return new_id;
end $$;

-- El cliente cancela su propia cita dentro del plazo
create function public.cancel_my_appointment(p_id uuid) returns void language plpgsql security definer set search_path = public as $$
declare ap appointments; hrs int;
begin
  select x.* into ap from appointments x join clients c on c.id = x.client_id where x.id = p_id and c.user_id = auth.uid();
  if not found or ap.status <> 'CONFIRMED' then raise exception 'cita_no_encontrada'; end if;
  select coalesce((config->>'cancelNoticeHours')::int, 0) into hrs from businesses where id = ap.business_id;
  if hrs > 0 and (ap.date + ap.start_time) - make_interval(hours => hrs) < lima_now() then raise exception 'fuera_de_plazo'; end if;
  update appointments set status = 'CANCELLED', cancelled_by = 'client', cancelled_at = now() where id = p_id;
end $$;

-- ============================================================
-- Funciones del superadmin
-- ============================================================
-- 1) Crear el usuario en Supabase → Authentication → Add user (con "Auto Confirm User").
-- 2) select public.create_business('Nombre', 'enlace', 'correo@admin.com');
create function public.create_business(p_name text, p_slug text, p_admin_email text) returns uuid
language plpgsql security definer set search_path = public, auth as $$
declare uid uuid; bid uuid;
begin
  if coalesce(my_role(), 'system') not in ('super', 'system') then raise exception 'solo_superadmin'; end if;
  select id into uid from auth.users where lower(email) = lower(p_admin_email);
  if uid is null then raise exception 'Primero crea el usuario %s en Authentication', p_admin_email; end if;
  insert into businesses (name, slug) values (p_name, p_slug) returning id into bid;
  insert into profiles (user_id, role, business_id, must_change) values (uid, 'admin', bid, true);
  return bid;
end $$;

create function public.make_super(p_email text) returns void language plpgsql security definer set search_path = public, auth as $$
declare uid uuid;
begin
  if coalesce(my_role(), 'system') not in ('super', 'system') then raise exception 'solo_superadmin'; end if;
  select id into uid from auth.users where lower(email) = lower(p_email);
  if uid is null then raise exception 'Primero crea el usuario %s en Authentication', p_email; end if;
  insert into profiles (user_id, role, must_change) values (uid, 'super', false) on conflict (user_id) do update set role = 'super', business_id = null;
end $$;

-- Permisos de ejecución: solo lo necesario
revoke execute on all functions in schema public from public, anon, authenticated;
grant execute on function public.public_business(text), public.public_busy(text, date, date) to anon, authenticated;
grant execute on function public.register_client(text, text, text, text, text, text), public.book_appointment(text, uuid, uuid, date, time), public.cancel_my_appointment(uuid) to authenticated;
grant execute on function public.my_role(), public.my_biz(), public.biz_ok(uuid), public.biz_status(uuid), public.lima_now(), public.covers(jsonb, time, time) to authenticated;
grant execute on function public.create_business(text, text, text), public.make_super(text) to authenticated;
