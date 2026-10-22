-- Caly · migración 002
-- Datos personales del administrador y permiso para unir clientes duplicados.
-- Pegar en Supabase → SQL Editor → Run (una sola vez).

alter table public.profiles add column if not exists display_name text not null default '';
alter table public.profiles add column if not exists phone text not null default '';

-- Unir clientes duplicados borra la ficha repetida (solo el administrador de ese negocio, por RLS).
grant delete on public.clients to authenticated;
