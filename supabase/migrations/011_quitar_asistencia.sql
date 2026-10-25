-- Caly · migración 011
-- Se elimina la columna "asistencia" de las citas (ya no se usa) y se actualiza el registro de actividad.
-- Pegar en Supabase → SQL Editor → Run (una sola vez).

create or replace function public.audit_appt() returns trigger language plpgsql security definer set search_path = public as $$
declare c clients; act text; txt text; who text;
begin
  select * into c from clients where id = new.client_id;
  who := c.nombres || ' ' || c.apellidos;
  if tg_op = 'INSERT' then
    act := 'appt.create'; txt := format('Se creó la cita del %s a las %s para %s.', new.date, to_char(new.start_time,'HH24:MI'), who);
  elsif new.status = 'CANCELLED' and old.status = 'CONFIRMED' then
    act := 'appt.cancel'; txt := format('Se canceló la cita del %s a las %s de %s (por %s).', new.date, to_char(new.start_time,'HH24:MI'), who, coalesce(new.cancelled_by, '—'));
  elsif new.paid is distinct from old.paid then
    act := 'appt.paid'; txt := format('Pago de %s (%s): %s.', who, new.date, case when new.paid then 'pagado' else 'pendiente' end);
  else return new; end if;
  insert into audit_log (business_id, role, actor_id, action, text, appt_id, doc)
  values (new.business_id, audit_actor_role(), auth.uid(), act, txt, new.id, c.doc);
  return new;
end $$;

alter table public.appointments drop column if exists attendance;
