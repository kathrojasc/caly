-- Caly · migración 008
-- Permite saber, antes de pedir contraseña, si un documento ya tiene cuenta (para mostrar "Ingresar" o "Crear cuenta").
-- Solo responde sí/no para correos internos de clientes. Pegar en Supabase → SQL Editor → Run (una sola vez).

create or replace function public.client_exists(p_email text) returns boolean
language sql security definer stable set search_path = public, auth as $$
  select p_email like '%@clientes.caly.pe' and exists (select 1 from auth.users where lower(email) = lower(p_email));
$$;
revoke execute on function public.client_exists(text) from public;
grant execute on function public.client_exists(text) to anon, authenticated;
