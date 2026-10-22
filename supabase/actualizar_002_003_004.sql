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
create policy cli_self_upd on public.clients for update to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());

create function public.protect_client() returns trigger language plpgsql as $$
begin
  -- Solo aplica a ediciones directas del cliente (rol authenticated); las funciones del sistema sí pueden vincular la ficha.
  if current_user in ('authenticated', 'anon') and coalesce(public.my_role(), 'client') = 'client'
     and (new.doc is distinct from old.doc or new.business_id is distinct from old.business_id
          or new.user_id is distinct from old.user_id or new.created_by is distinct from old.created_by or new.doc_type is distinct from old.doc_type) then
    raise exception 'No puedes cambiar tu documento';
  end if;
  return new;
end $$;
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
