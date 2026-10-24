-- Caly · migración 009
-- Cuenta "Pendiente de activación": la prueba de 14 días empieza cuando el administrador crea su contraseña, no al crear la cuenta.
-- Pegar en Supabase → SQL Editor → Run (una sola vez).

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
