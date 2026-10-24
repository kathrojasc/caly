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
