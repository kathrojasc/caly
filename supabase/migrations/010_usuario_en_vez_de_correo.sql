-- Caly · migración 010
-- Los administradores y el superadmin entran con un NOMBRE DE USUARIO (no con un correo real).
-- Internamente se guarda como <usuario>@usuarios.caly.pe; ese correo no existe ni se muestra.
-- Pegar en Supabase → SQL Editor → Run (una sola vez).

-- Función interna: cambia el correo de acceso de un usuario (solo desde el SQL Editor).
create or replace function public.rename_user(p_old text, p_new text) returns void
language plpgsql security definer set search_path = public, auth as $$
declare uid uuid;
begin
  if lower(p_old) = lower(p_new) then return; end if;
  select id into uid from auth.users where lower(email) = lower(p_old);
  if uid is null then raise exception 'usuario_no_encontrado'; end if;
  if exists (select 1 from auth.users where lower(email) = lower(p_new)) then raise exception 'usuario_existe'; end if;
  update auth.users set email = lower(p_new), updated_at = now() where id = uid;
  if to_regclass('auth.identities') is not null then
    execute 'update auth.identities set identity_data = jsonb_set(coalesce(identity_data, ''{}''::jsonb), ''{email}'', to_jsonb($1::text)), provider_id = $1, updated_at = now() where user_id = $2 and provider = ''email'''
    using lower(p_new), uid;
  end if;
  update public.businesses set admin_email = lower(p_new) where lower(admin_email) = lower(p_old);
end $$;
revoke execute on function public.rename_user(text, text) from public, anon, authenticated;

-- El superadmin cambia el usuario de un administrador.
create or replace function public.rename_admin_user(p_business uuid, p_username text) returns void
language plpgsql security definer set search_path = public, auth as $$
declare old_email text; u text := lower(trim(p_username));
begin
  if coalesce(my_role(), 'system') not in ('super', 'system') then raise exception 'solo_superadmin'; end if;
  if u !~ '^[a-z0-9._-]{3,30}$' then raise exception 'usuario_invalido'; end if;
  select admin_email into old_email from businesses where id = p_business;
  if old_email is null then raise exception 'perfil_no_encontrado'; end if;
  perform public.rename_user(old_email, u || '@usuarios.caly.pe');
  insert into audit_log (business_id, role, actor_id, action, text)
  values (p_business, coalesce(my_role(), 'system'), auth.uid(), 'admin.rename', format('Se cambió el usuario del administrador a "%s".', u));
end $$;
revoke execute on function public.rename_admin_user(uuid, text) from public, anon;
grant execute on function public.rename_admin_user(uuid, text) to authenticated;
