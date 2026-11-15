create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  display_name text,
  role text not null default 'player' check (role in ('player','admin')),
  wallet_balance numeric(12,2) not null default 0 check (wallet_balance >= 0),
  created_at timestamptz not null default now()
);
create table if not exists public.tournaments (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  description text,
  entry_fee numeric(12,2) not null default 0 check(entry_fee >= 0),
  prize_pool numeric(12,2) not null default 0 check(prize_pool >= 0),
  slots integer not null default 48 check(slots > 0),
  starts_at timestamptz,
  status text not null default 'upcoming' check(status in ('upcoming','open','live','completed','cancelled')),
  created_at timestamptz not null default now()
);
create table if not exists public.registrations (
  id uuid primary key default gen_random_uuid(),
  tournament_id uuid not null references public.tournaments(id) on delete cascade,
  player_id uuid not null references public.profiles(id) on delete cascade,
  team_name text,
  game_uid text not null,
  status text not null default 'pending' check(status in ('pending','approved','rejected')),
  created_at timestamptz not null default now(),
  unique(tournament_id, player_id)
);
create table if not exists public.announcements (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  body text not null,
  is_active boolean not null default true,
  created_by uuid references public.profiles(id),
  created_at timestamptz not null default now()
);
create table if not exists public.payment_requests (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id),
  amount numeric(12,2) not null check(amount > 0),
  method text not null check(method in ('bkash','nagad','rocket')),
  transaction_ref text not null,
  sender_number text,
  proof_path text,
  status text not null default 'pending' check(status in ('pending','approved','rejected')),
  reviewed_by uuid references public.profiles(id),
  reviewed_at timestamptz,
  created_at timestamptz not null default now()
);
create table if not exists public.wallet_transactions (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id),
  payment_request_id uuid unique references public.payment_requests(id),
  amount numeric(12,2) not null,
  kind text not null check(kind in ('deposit','withdrawal','entry_fee','prize','refund','adjustment')),
  created_at timestamptz not null default now()
);

create or replace function public.is_admin()
returns boolean language sql stable security definer set search_path=public
as $$ select exists(select 1 from public.profiles where id=auth.uid() and role='admin'); $$;

create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path=public
as $$ begin
 insert into public.profiles(id,display_name) values(new.id, coalesce(new.raw_user_meta_data->>'display_name','Player'));
 return new;
end; $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
for each row execute procedure public.handle_new_user();

alter table public.profiles enable row level security;
alter table public.tournaments enable row level security;
alter table public.registrations enable row level security;
alter table public.announcements enable row level security;
alter table public.payment_requests enable row level security;
alter table public.wallet_transactions enable row level security;

create policy "profiles read own or admin" on public.profiles for select to authenticated
using (id=auth.uid() or public.is_admin());
create policy "profiles update own display only via restricted columns" on public.profiles for update to authenticated
using (id=auth.uid() or public.is_admin())
with check (id=auth.uid() or public.is_admin());
-- IMPORTANT: do not grant clients UPDATE on role or wallet_balance; revoke table-wide update below.
revoke update on public.profiles from authenticated;
grant update(display_name) on public.profiles to authenticated;

create policy "tournaments visible" on public.tournaments for select to anon,authenticated using (true);
create policy "admins manage tournaments" on public.tournaments for all to authenticated
using (public.is_admin()) with check (public.is_admin());

create policy "players read own registrations" on public.registrations for select to authenticated
using (player_id=auth.uid() or public.is_admin());
create policy "players create own registration" on public.registrations for insert to authenticated
with check (player_id=auth.uid());
create policy "admins manage registrations" on public.registrations for update to authenticated
using(public.is_admin()) with check(public.is_admin());

create policy "active announcements public" on public.announcements for select to anon,authenticated
using(is_active=true or public.is_admin());
create policy "admins create announcements" on public.announcements for insert to authenticated
with check(public.is_admin() and created_by=auth.uid());
create policy "admins update announcements" on public.announcements for update to authenticated
using(public.is_admin()) with check(public.is_admin());
create policy "admins delete announcements" on public.announcements for delete to authenticated
using(public.is_admin());

create policy "players read own payments" on public.payment_requests for select to authenticated
using(user_id=auth.uid() or public.is_admin());
create policy "players create own payment requests" on public.payment_requests for insert to authenticated
with check(user_id=auth.uid() and status='pending');
create policy "admins review payments" on public.payment_requests for update to authenticated
using(public.is_admin()) with check(public.is_admin());

create policy "wallet transactions owner or admin read" on public.wallet_transactions for select to authenticated
using(user_id=auth.uid() or public.is_admin());
-- No client insert/update/delete policies on wallet_transactions.

create or replace function public.admin_approve_payment(request_id uuid)
returns void language plpgsql security definer set search_path=public
as $$
declare r public.payment_requests%rowtype;
begin
 if not public.is_admin() then raise exception 'Admin access required'; end if;
 select * into r from public.payment_requests where id=request_id for update;
 if not found then raise exception 'Payment request not found'; end if;
 if r.status <> 'pending' then raise exception 'Payment request already reviewed'; end if;
 update public.payment_requests set status='approved', reviewed_by=auth.uid(), reviewed_at=now() where id=r.id;
 update public.profiles set wallet_balance=wallet_balance+r.amount where id=r.user_id;
 insert into public.wallet_transactions(user_id,payment_request_id,amount,kind)
 values(r.user_id,r.id,r.amount,'deposit');
end; $$;
revoke all on function public.admin_approve_payment(uuid) from public;
grant execute on function public.admin_approve_payment(uuid) to authenticated;

grant select on public.tournaments,public.announcements to anon,authenticated;
grant select,insert on public.registrations to authenticated;
grant select,insert,update,delete on public.announcements to authenticated;
grant select,insert,update on public.payment_requests to authenticated;
grant select on public.profiles,public.wallet_transactions to authenticated;


-- Manual bKash / Nagad / Rocket merchant instructions.
create table if not exists public.merchant_payment_settings (
  method text primary key check (method in ('bkash','nagad','rocket')),
  merchant_number text not null,
  account_type text not null default 'Personal' check (account_type in ('Personal','Merchant','Agent')),
  instructions text,
  is_enabled boolean not null default true,
  updated_at timestamptz not null default now(),
  updated_by uuid references public.profiles(id)
);
alter table public.merchant_payment_settings enable row level security;

drop policy if exists "public read enabled merchant methods" on public.merchant_payment_settings;
create policy "public read enabled merchant methods"
on public.merchant_payment_settings for select to anon, authenticated
using (is_enabled = true or public.is_admin());

drop policy if exists "admins manage merchant settings" on public.merchant_payment_settings;
create policy "admins manage merchant settings"
on public.merchant_payment_settings for all to authenticated
using (public.is_admin()) with check (public.is_admin());

create unique index if not exists payment_provider_txn_unique
on public.payment_requests(method, lower(transaction_ref));

drop policy if exists "admins review payments" on public.payment_requests;
revoke update on public.payment_requests from authenticated;
grant select, insert on public.payment_requests to authenticated;
grant select on public.merchant_payment_settings to anon, authenticated;
grant insert, update, delete on public.merchant_payment_settings to authenticated;

drop policy if exists "players create own payment requests" on public.payment_requests;
create policy "players create own pending payment requests"
on public.payment_requests for insert to authenticated
with check (
  user_id = auth.uid()
  and status = 'pending'
  and reviewed_by is null
  and reviewed_at is null
);
