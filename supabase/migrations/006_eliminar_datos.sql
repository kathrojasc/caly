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
