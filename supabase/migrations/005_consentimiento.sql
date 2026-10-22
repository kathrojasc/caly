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
