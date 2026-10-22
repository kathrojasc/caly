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
