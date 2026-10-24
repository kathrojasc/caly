-- Caly · migración 002
-- Datos personales del administrador y permiso para unir clientes duplicados.
-- Pegar en Supabase → SQL Editor → Run (una sola vez).

alter table public.profiles add column if not exists display_name text not null default '';
alter table public.profiles add column if not exists phone text not null default '';

-- Unir clientes duplicados borra la ficha repetida (solo el administrador de ese negocio, por RLS).
grant delete on public.clients to authenticated;
-- Caly · migración 003
-- Clientes: validar teléfono al activar una ficha creada por el negocio, y permitir que editen sus propios datos.
-- Pegar en Supabase → SQL Editor → Run (una sola vez).

create or replace function public.register_client(p_slug text, p_doc_type text, p_doc text, p_nombres text, p_apellidos text, p_phone text) returns uuid
language plpgsql security definer set search_path = public as $$
declare b businesses; c clients;
begin
  if auth.uid() is null then raise exception 'sin_sesion'; end if;
  select * into b from businesses where slug = p_slug;
  if not found or not biz_ok(b.id) then raise exception 'negocio_no_disponible'; end if;
  select * into c from clients where business_id = b.id and doc = p_doc;
  if found then
    if c.user_id is not null and c.user_id <> auth.uid() then raise exception 'documento_ya_registrado'; end if;
    -- La ficha la creó el negocio: solo se activa con el mismo teléfono que le dio el cliente.
    if c.user_id is null and regexp_replace(c.phone, '\D', '', 'g') <> '' and regexp_replace(c.phone, '\D', '', 'g') <> regexp_replace(p_phone, '\D', '', 'g') then
      raise exception 'telefono_no_coincide';
    end if;
    update clients set user_id = auth.uid(), doc_type = p_doc_type, nombres = p_nombres, apellidos = p_apellidos, phone = p_phone where id = c.id;
    return c.id;
  end if;
  insert into clients (business_id, user_id, doc_type, doc, nombres, apellidos, phone, created_by)
  values (b.id, auth.uid(), p_doc_type, p_doc, p_nombres, p_apellidos, p_phone, 'client') returning id into c.id;
  return c.id;
end $$;
revoke execute on function public.register_client(text, text, text, text, text, text) from public, anon;
grant execute on function public.register_client(text, text, text, text, text, text) to authenticated;

-- El cliente puede editar sus datos de contacto, pero no su documento ni a qué negocio pertenece.
drop policy if exists cli_self_upd on public.clients;
create policy cli_self_upd on public.clients for update to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());

create or replace function public.protect_client() returns trigger language plpgsql as $$
begin
  -- Solo aplica a ediciones directas del cliente (rol authenticated); las funciones del sistema sí pueden vincular la ficha.
  if current_user in ('authenticated', 'anon') and coalesce(public.my_role(), 'client') = 'client'
     and (new.doc is distinct from old.doc or new.business_id is distinct from old.business_id
          or new.user_id is distinct from old.user_id or new.created_by is distinct from old.created_by or new.doc_type is distinct from old.doc_type) then
    raise exception 'No puedes cambiar tu documento';
  end if;
  return new;
end $$;
drop trigger if exists protect_client on public.clients;
create trigger protect_client before update on public.clients for each row execute function public.protect_client();
-- Caly · migración 004
-- El superadmin ve el correo de cada administrador. Pegar en Supabase → SQL Editor → Run (una sola vez).

alter table public.businesses add column if not exists admin_email text;

update public.businesses b set admin_email = (
  select u.email from public.profiles p join auth.users u on u.id = p.user_id
  where p.business_id = b.id and p.role = 'admin' limit 1)
where admin_email is null;

create or replace function public.create_business(p_name text, p_slug text, p_admin_email text) returns uuid
language plpgsql security definer set search_path = public, auth as $$
declare uid uuid; bid uuid;
begin
  if coalesce(my_role(), 'system') not in ('super', 'system') then raise exception 'solo_superadmin'; end if;
  select id into uid from auth.users where lower(email) = lower(p_admin_email);
  if uid is null then raise exception 'Primero crea el usuario % en Authentication', p_admin_email; end if;
  insert into businesses (name, slug, admin_email) values (p_name, p_slug, lower(p_admin_email)) returning id into bid;
  insert into profiles (user_id, role, business_id, must_change) values (uid, 'admin', bid, true);
  return bid;
end $$;
revoke execute on function public.create_business(text, text, text) from public, anon;
grant execute on function public.create_business(text, text, text) to authenticated;
-- Caly · migración 005
-- Consentimiento: se guarda quién aceptó, cuándo y qué versión del texto.
-- Pegar en Supabase → SQL Editor → Run (una sola vez).

alter table public.clients  add column if not exists consent_at timestamptz;
alter table public.clients  add column if not exists consent_version text;
alter table public.profiles add column if not exists terms_at timestamptz;
alter table public.profiles add column if not exists terms_version text;

-- Registro del cliente: ahora exige aceptar la política de privacidad.
drop function if exists public.register_client(text, text, text, text, text, text);
drop function if exists public.register_client(text, text, text, text, text, text, text);
create function public.register_client(p_slug text, p_doc_type text, p_doc text, p_nombres text, p_apellidos text, p_phone text, p_consent text) returns uuid
language plpgsql security definer set search_path = public as $$
declare b businesses; c clients;
begin
  if auth.uid() is null then raise exception 'sin_sesion'; end if;
  if coalesce(p_consent, '') = '' then raise exception 'consentimiento_requerido'; end if;
  select * into b from businesses where slug = p_slug;
  if not found or not biz_ok(b.id) then raise exception 'negocio_no_disponible'; end if;
  select * into c from clients where business_id = b.id and doc = p_doc;
  if found then
    if c.user_id is not null and c.user_id <> auth.uid() then raise exception 'documento_ya_registrado'; end if;
    if c.user_id is null and regexp_replace(c.phone, '\D', '', 'g') <> '' and regexp_replace(c.phone, '\D', '', 'g') <> regexp_replace(p_phone, '\D', '', 'g') then
      raise exception 'telefono_no_coincide';
    end if;
    update clients set user_id = auth.uid(), doc_type = p_doc_type, nombres = p_nombres, apellidos = p_apellidos, phone = p_phone,
           consent_at = now(), consent_version = p_consent where id = c.id;
  else
    insert into clients (business_id, user_id, doc_type, doc, nombres, apellidos, phone, created_by, consent_at, consent_version)
    values (b.id, auth.uid(), p_doc_type, p_doc, p_nombres, p_apellidos, p_phone, 'client', now(), p_consent) returning id into c.id;
  end if;
  insert into audit_log (business_id, role, actor_id, action, text, doc)
  values (b.id, 'client', auth.uid(), 'client.consent', format('%s %s aceptó la política de privacidad (versión %s).', p_nombres, p_apellidos, p_consent), p_doc);
  return c.id;
end $$;
revoke execute on function public.register_client(text, text, text, text, text, text, text) from public, anon;
grant execute on function public.register_client(text, text, text, text, text, text, text) to authenticated;

-- Administrador (y superadmin): acepta los términos de uso y la política de privacidad.
create or replace function public.accept_terms(p_version text) returns void language plpgsql security definer set search_path = public as $$
declare p profiles;
begin
  if coalesce(p_version, '') = '' then raise exception 'consentimiento_requerido'; end if;
  select * into p from profiles where user_id = auth.uid();
  if not found then raise exception 'sin_sesion'; end if;
  update profiles set terms_at = now(), terms_version = p_version where user_id = auth.uid();
  insert into audit_log (business_id, role, actor_id, action, text)
  values (p.business_id, p.role, auth.uid(), 'terms.accept', format('Aceptó los términos de uso y la política de privacidad (versión %s).', p_version));
end $$;
revoke execute on function public.accept_terms(text) from public, anon;
grant execute on function public.accept_terms(text) to authenticated;

-- Las marcas de consentimiento no se pueden editar a mano: solo las escriben las funciones de arriba.
create or replace function public.protect_client() returns trigger language plpgsql as $$
begin
  if current_user in ('authenticated', 'anon') and coalesce(public.my_role(), 'client') = 'client'
     and (new.doc is distinct from old.doc or new.business_id is distinct from old.business_id
          or new.user_id is distinct from old.user_id or new.created_by is distinct from old.created_by or new.doc_type is distinct from old.doc_type
          or new.consent_at is distinct from old.consent_at or new.consent_version is distinct from old.consent_version) then
    raise exception 'No puedes cambiar tu documento';
  end if;
  return new;
end $$;

create or replace function public.protect_profile() returns trigger language plpgsql as $$
begin
  if coalesce(public.my_role(), 'system') not in ('super', 'system')
     and (new.role is distinct from old.role or new.business_id is distinct from old.business_id) then
    raise exception 'No puedes cambiar tu rol';
  end if;
  if current_user in ('authenticated', 'anon')
     and (new.terms_at is distinct from old.terms_at or new.terms_version is distinct from old.terms_version) then
    raise exception 'No puedes cambiar esa información';
  end if;
  return new;
end $$;
-- Caly · migración 006
-- Eliminar los datos de un negocio (fin del periodo de prueba): citas, clientes, trabajadores, servicios y cierres.
-- La cuenta del negocio queda desactivada y el registro de actividad conserva solo quién hizo qué y cuándo, sin datos personales.
-- Pegar en Supabase → SQL Editor → Run (una sola vez; se puede repetir sin problema).

-- Mientras se elimina un negocio, los registros automáticos no vuelven a copiar datos personales.
create or replace function public.audit_generic() returns trigger language plpgsql security definer set search_path = public as $$
declare r record; b uuid; label text;
begin
  if coalesce(current_setting('caly.purging', true), '') = 'on' then
    return case when tg_op = 'DELETE' then old else new end;
  end if;
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

create or replace function public.audit_immutable() returns trigger language plpgsql as $$
begin
  if coalesce(current_setting('caly.purging', true), '') = 'on' and tg_op = 'UPDATE' then return new; end if;
  raise exception 'El registro de actividad no se puede modificar';
end $$;

create or replace function public.purge_business(p_business uuid) returns void language plpgsql security definer set search_path = public, auth as $$
declare client_users uuid[]; nb int;
begin
  if coalesce(my_role(), 'system') not in ('super', 'system') then raise exception 'solo_superadmin'; end if;
  perform set_config('caly.purging', 'on', true);
  select coalesce(array_agg(user_id), '{}') into client_users from clients where business_id = p_business and user_id is not null;
  delete from appointments where business_id = p_business;
  delete from clients where business_id = p_business;
  delete from closures where business_id = p_business;
  delete from services where business_id = p_business;
  delete from staff where business_id = p_business;
  -- Cuentas de acceso de los clientes (nunca las de administradores ni superadmin)
  delete from auth.users where id = any (client_users) and id not in (select user_id from profiles);
  -- El registro de actividad se conserva sin datos personales
  update audit_log set text = '(detalle eliminado al dar de baja el negocio)', data = null, doc = null
   where business_id = p_business and action not in ('super.purge');
  update businesses set enabled = false, business_hours = '{}', brand = '{}' where id = p_business;
  perform set_config('caly.purging', 'off', true);
  insert into audit_log (business_id, role, actor_id, action, text)
  values (p_business, coalesce(my_role(), 'system'), auth.uid(), 'super.purge', 'Se eliminaron los datos del negocio (citas, clientes, trabajadores y servicios) y se desactivó la cuenta.');
end $$;
revoke execute on function public.purge_business(uuid) from public, anon;
grant execute on function public.purge_business(uuid) to authenticated;
-- Caly · migración 007
-- Contraseña temporal: el administrador se la genera a un cliente que olvidó la suya,
-- y el superadmin a un administrador. La persona deberá cambiarla al ingresar.
-- Pegar en Supabase → SQL Editor → Run (una sola vez; se puede repetir sin problema).

create extension if not exists pgcrypto with schema extensions;

alter table public.clients add column if not exists must_change boolean not null default false;

-- Genera una contraseña de 8 caracteres fácil de dictar (sin 0/O, 1/l/I)
create or replace function public.gen_temp_password() returns text language plpgsql volatile set search_path = public, extensions as $$
declare chars text := 'abcdefghjkmnpqrstuvwxyzACDEFGHJKLMNPQRTUVWXYZ23456789'; out text := ''; b bytea := extensions.gen_random_bytes(8); i int;
begin
  for i in 0..7 loop out := out || substr(chars, (get_byte(b, i) % length(chars)) + 1, 1); end loop;
  return out;
end $$;
revoke execute on function public.gen_temp_password() from public, anon, authenticated;

create or replace function public.reset_client_password(p_client uuid) returns text
language plpgsql security definer set search_path = public, auth, extensions as $$
declare c clients; pw text; r text := coalesce(my_role(), 'system');
begin
  select * into c from clients where id = p_client;
  if not found then raise exception 'cita_no_encontrada'; end if;
  if r = 'admin' then
    if c.business_id is distinct from my_biz() or not biz_ok(c.business_id) then raise exception 'solo_superadmin'; end if;
  elsif r not in ('super', 'system') then
    raise exception 'solo_superadmin';
  end if;
  if c.user_id is null then raise exception 'cliente_sin_cuenta'; end if;
  if exists (select 1 from profiles where user_id = c.user_id) then raise exception 'solo_superadmin'; end if;
  pw := gen_temp_password();
  update auth.users set encrypted_password = extensions.crypt(pw, extensions.gen_salt('bf')), updated_at = now() where id = c.user_id;
  update clients set must_change = true where id = c.id;
  insert into audit_log (business_id, role, actor_id, action, text, doc)
  values (c.business_id, r, auth.uid(), 'client.password_reset', format('Se generó una contraseña temporal para %s %s.', c.nombres, c.apellidos), c.doc);
  return pw;
end $$;
revoke execute on function public.reset_client_password(uuid) from public, anon;
grant execute on function public.reset_client_password(uuid) to authenticated;

create or replace function public.reset_admin_password(p_business uuid) returns text
language plpgsql security definer set search_path = public, auth, extensions as $$
declare uid uuid; pw text;
begin
  if coalesce(my_role(), 'system') not in ('super', 'system') then raise exception 'solo_superadmin'; end if;
  select user_id into uid from profiles where business_id = p_business and role = 'admin' limit 1;
  if uid is null then raise exception 'perfil_no_encontrado'; end if;
  pw := gen_temp_password();
  update auth.users set encrypted_password = extensions.crypt(pw, extensions.gen_salt('bf')), updated_at = now() where id = uid;
  update profiles set must_change = true where user_id = uid;
  insert into audit_log (business_id, role, actor_id, action, text)
  values (p_business, coalesce(my_role(), 'system'), auth.uid(), 'admin.password_reset', 'Se generó una contraseña temporal para el administrador del negocio.');
  return pw;
end $$;
revoke execute on function public.reset_admin_password(uuid) from public, anon;
grant execute on function public.reset_admin_password(uuid) to authenticated;

-- ===== 008 =====

create or replace function public.client_exists(p_email text) returns boolean
language sql security definer stable set search_path = public, auth as $$
  select p_email like '%@clientes.caly.pe' and exists (select 1 from auth.users where lower(email) = lower(p_email));
$$;
revoke execute on function public.client_exists(text) from public;
grant execute on function public.client_exists(text) to anon, authenticated;

-- ===== 009 =====

alter table public.businesses add column if not exists activated_at timestamptz;
alter table public.businesses alter column trial_ends_at drop default;

-- Cuentas que ya existen: las que ya cambiaron su contraseña quedan activadas; las demás, pendientes.
update public.businesses b set activated_at = b.created_at
where b.activated_at is null
  and exists (select 1 from public.profiles p where p.business_id = b.id and p.role = 'admin' and (p.must_change = false or p.terms_at is not null));
update public.businesses set trial_ends_at = null where activated_at is null and plan = 'Prueba';

-- Solo el superadmin puede tocar plan, cobro, estado, enlace o activación (el trigger de activación sí, por ser interno).
create or replace function public.protect_business() returns trigger language plpgsql as $$
begin
  if current_user in ('authenticated', 'anon')
     and coalesce(public.my_role(), 'system') not in ('super', 'system') and (
       new.plan is distinct from old.plan or new.enabled is distinct from old.enabled
    or new.trial_ends_at is distinct from old.trial_ends_at or new.last_paid_at is distinct from old.last_paid_at
    or new.next_pay_at is distinct from old.next_pay_at or new.slug is distinct from old.slug
    or new.activated_at is distinct from old.activated_at) then
    raise exception 'Solo el superadmin puede cambiar plan, cobro, estado o enlace';
  end if;
  return new;
end $$;

-- Al crear su contraseña por primera vez, el administrador activa la cuenta y empieza su plan.
create or replace function public.activate_business() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if new.role = 'admin' and old.must_change and not new.must_change then
    update businesses set
      activated_at = now(),
      trial_ends_at = case when plan = 'Prueba' then (((lima_now()::date + 14) + time '23:59:59') at time zone 'America/Lima') else trial_ends_at end
    where id = new.business_id and activated_at is null;
  end if;
  return new;
end $$;
drop trigger if exists activate_business on public.profiles;
create trigger activate_business after update of must_change on public.profiles for each row execute function public.activate_business();
