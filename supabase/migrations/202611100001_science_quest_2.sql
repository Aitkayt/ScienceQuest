-- Science Quest 2.0 foundation
-- Run in Supabase SQL Editor after taking a database backup.
-- Promote admins only from a trusted server/dashboard by setting app_metadata.role = 'admin'.
create extension if not exists pgcrypto;

create table if not exists public.sq_groups (
  id uuid primary key default gen_random_uuid(),
  name text not null check (length(trim(name)) between 1 and 80),
  created_by uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);
create table if not exists public.sq_worlds (
  id uuid primary key default gen_random_uuid(),
  group_id uuid not null references public.sq_groups(id) on delete cascade,
  name text not null check (length(trim(name)) between 1 and 100),
  description text not null default '',
  payload jsonb not null,
  published boolean not null default false,
  created_by uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);
create table if not exists public.sq_inventory (
  user_id uuid not null references auth.users(id) on delete cascade,
  item_id text not null check (length(item_id) between 1 and 80),
  quantity integer not null default 0 check (quantity >= 0),
  primary key(user_id,item_id)
);
create table if not exists public.sq_trades (
  id uuid primary key default gen_random_uuid(),
  sender_id uuid not null references auth.users(id) on delete cascade,
  recipient_id uuid not null references auth.users(id) on delete cascade,
  offer jsonb not null,
  request jsonb not null,
  status text not null default 'pending' check (status in ('pending','accepted','rejected','cancelled')),
  created_at timestamptz not null default now(),
  responded_at timestamptz,
  check (sender_id <> recipient_id),
  check (jsonb_typeof(offer) = 'array' and jsonb_typeof(request) = 'array')
);
create index if not exists sq_trades_recipient_pending_idx
  on public.sq_trades(recipient_id,created_at desc) where status='pending';
create table if not exists public.sq_quests (
  quest_id text not null,
  period text not null check (period in ('weekly','monthly')),
  title text not null,
  target integer not null check (target > 0),
  reward_item text not null,
  reward_qty integer not null check (reward_qty > 0),
  active boolean not null default true,
  primary key(quest_id,period)
);
create table if not exists public.sq_quest_progress (
  user_id uuid not null references auth.users(id) on delete cascade,
  quest_id text not null,
  period text not null check (period in ('weekly','monthly')),
  period_start date not null,
  progress integer not null default 0 check (progress >= 0),
  primary key(user_id,quest_id,period,period_start)
);
create table if not exists public.sq_quest_claims (
  user_id uuid not null references auth.users(id) on delete cascade,
  quest_id text not null,
  period text not null check (period in ('weekly','monthly')),
  period_start date not null,
  claimed_at timestamptz not null default now(),
  primary key(user_id,quest_id,period,period_start)
);

-- Admin is a trusted app_metadata claim, never user_metadata or a client-editable profile field.
create or replace function public.sq_is_admin()
returns boolean language sql stable security invoker
set search_path = ''
as $$
  select coalesce((auth.jwt() -> 'app_metadata' ->> 'role') = 'admin', false);
$$;

alter table public.sq_groups enable row level security;
alter table public.sq_worlds enable row level security;
alter table public.sq_inventory enable row level security;
alter table public.sq_trades enable row level security;
alter table public.sq_quests enable row level security;
alter table public.sq_quest_progress enable row level security;
alter table public.sq_quest_claims enable row level security;

-- Remove broad defaults first; then grant only what policies expose.
revoke all on public.sq_groups, public.sq_worlds, public.sq_inventory,
  public.sq_trades, public.sq_quests, public.sq_quest_progress,
  public.sq_quest_claims from anon, authenticated;
grant select, insert, update, delete on public.sq_groups, public.sq_worlds, public.sq_quests to authenticated;
grant select on public.sq_inventory, public.sq_trades,
  public.sq_quest_progress, public.sq_quest_claims to authenticated;

drop policy if exists sq_groups_read on public.sq_groups;
create policy sq_groups_read on public.sq_groups for select to authenticated using (true);
drop policy if exists sq_groups_admin_all on public.sq_groups;
create policy sq_groups_admin_all on public.sq_groups for all to authenticated
  using (public.sq_is_admin()) with check (public.sq_is_admin());

drop policy if exists sq_worlds_read on public.sq_worlds;
create policy sq_worlds_read on public.sq_worlds for select to authenticated
  using (published or created_by = (select auth.uid()) or public.sq_is_admin());
drop policy if exists sq_worlds_admin_all on public.sq_worlds;
create policy sq_worlds_admin_all on public.sq_worlds for all to authenticated
  using (public.sq_is_admin()) with check (public.sq_is_admin());

drop policy if exists sq_inventory_read_self on public.sq_inventory;
create policy sq_inventory_read_self on public.sq_inventory for select to authenticated
  using (user_id = (select auth.uid()));
drop policy if exists sq_trades_read_party on public.sq_trades;
create policy sq_trades_read_party on public.sq_trades for select to authenticated
  using (sender_id = (select auth.uid()) or recipient_id = (select auth.uid()));
drop policy if exists sq_quests_read on public.sq_quests;
create policy sq_quests_read on public.sq_quests for select to authenticated using (active or public.sq_is_admin());
drop policy if exists sq_quests_admin_all on public.sq_quests;
create policy sq_quests_admin_all on public.sq_quests for all to authenticated
  using (public.sq_is_admin()) with check (public.sq_is_admin());
drop policy if exists sq_progress_read_self on public.sq_quest_progress;
create policy sq_progress_read_self on public.sq_quest_progress for select to authenticated
  using (user_id = (select auth.uid()));
drop policy if exists sq_claims_read_self on public.sq_quest_claims;
create policy sq_claims_read_self on public.sq_quest_claims for select to authenticated
  using (user_id = (select auth.uid()));

-- Inventory and trade writes are RPC-only. No direct INSERT/UPDATE/DELETE grants.
create or replace function public.sq_create_trade(
  p_recipient uuid, p_offer jsonb, p_request jsonb
) returns uuid
language plpgsql security definer set search_path = ''
as $$
declare v_id uuid; v_item jsonb; v_qty int; v_item_id text;
begin
  if auth.uid() is null or p_recipient = auth.uid() then raise exception 'invalid recipient'; end if;
  if jsonb_typeof(p_offer) <> 'array' or jsonb_typeof(p_request) <> 'array'
     or jsonb_array_length(p_offer) > 10 or jsonb_array_length(p_request) > 10 then
    raise exception 'invalid trade payload';
  end if;
  for v_item in select value from jsonb_array_elements(p_offer) loop
    v_item_id := v_item->>'item_id'; v_qty := (v_item->>'quantity')::int;
    if v_item_id is null or v_qty is null or v_qty < 1 or v_qty > 99 then raise exception 'invalid offer item'; end if;
    if coalesce((select quantity from public.sq_inventory where user_id=auth.uid() and item_id=v_item_id),0) < v_qty then
      raise exception 'not enough offered items';
    end if;
  end loop;
  insert into public.sq_trades(sender_id,recipient_id,offer,request)
  values(auth.uid(),p_recipient,p_offer,p_request) returning id into v_id;
  return v_id;
end $$;

create or replace function public.sq_respond_trade(p_trade uuid, p_accept boolean)
returns void language plpgsql security definer set search_path = ''
as $$
declare t public.sq_trades%rowtype; v_item jsonb; v_item_id text; v_qty int;
begin
  select * into t from public.sq_trades where id=p_trade for update;
  if not found or t.recipient_id <> auth.uid() or t.status <> 'pending' then raise exception 'trade unavailable'; end if;
  if not p_accept then
    update public.sq_trades set status='rejected',responded_at=now() where id=p_trade;
    return;
  end if;
  -- Check both sides before any mutation; transaction rollback guarantees atomic exchange.
  for v_item in select value from jsonb_array_elements(t.offer) loop
    v_item_id:=v_item->>'item_id'; v_qty:=(v_item->>'quantity')::int;
    if coalesce((select quantity from public.sq_inventory where user_id=t.sender_id and item_id=v_item_id for update),0)<v_qty then raise exception 'sender inventory changed'; end if;
  end loop;
  for v_item in select value from jsonb_array_elements(t.request) loop
    v_item_id:=v_item->>'item_id'; v_qty:=(v_item->>'quantity')::int;
    if v_item_id is null or v_qty is null or v_qty<1 or v_qty>99 then raise exception 'invalid requested item'; end if;
    if coalesce((select quantity from public.sq_inventory where user_id=auth.uid() and item_id=v_item_id for update),0)<v_qty then raise exception 'not enough requested items'; end if;
  end loop;
  for v_item in select value from jsonb_array_elements(t.offer) loop
    v_item_id:=v_item->>'item_id'; v_qty:=(v_item->>'quantity')::int;
    update public.sq_inventory set quantity=quantity-v_qty where user_id=t.sender_id and item_id=v_item_id;
    insert into public.sq_inventory(user_id,item_id,quantity) values(auth.uid(),v_item_id,v_qty)
      on conflict(user_id,item_id) do update set quantity=public.sq_inventory.quantity+excluded.quantity;
  end loop;
  for v_item in select value from jsonb_array_elements(t.request) loop
    v_item_id:=v_item->>'item_id'; v_qty:=(v_item->>'quantity')::int;
    update public.sq_inventory set quantity=quantity-v_qty where user_id=auth.uid() and item_id=v_item_id;
    insert into public.sq_inventory(user_id,item_id,quantity) values(t.sender_id,v_item_id,v_qty)
      on conflict(user_id,item_id) do update set quantity=public.sq_inventory.quantity+excluded.quantity;
  end loop;
  update public.sq_trades set status='accepted',responded_at=now() where id=p_trade;
end $$;

-- Period boundaries are derived by the database (UTC), not supplied by the client.
create or replace function public.sq_claim_quest(p_quest_id text, p_period text)
returns void language plpgsql security definer set search_path = ''
as $$
declare q public.sq_quests%rowtype; d date; v_progress int;
begin
  if auth.uid() is null then raise exception 'authentication required'; end if;
  if p_period='weekly' then d:=date_trunc('week',now() at time zone 'UTC')::date;
  elsif p_period='monthly' then d:=date_trunc('month',now() at time zone 'UTC')::date;
  else raise exception 'invalid period'; end if;
  select * into q from public.sq_quests where quest_id=p_quest_id and period=p_period and active;
  if not found then raise exception 'quest unavailable'; end if;
  select progress into v_progress from public.sq_quest_progress
   where user_id=auth.uid() and quest_id=p_quest_id and period=p_period and period_start=d;
  if coalesce(v_progress,0)<q.target then raise exception 'quest not completed'; end if;
  insert into public.sq_quest_claims(user_id,quest_id,period,period_start)
   values(auth.uid(),p_quest_id,p_period,d);
  insert into public.sq_inventory(user_id,item_id,quantity)
   values(auth.uid(),q.reward_item,q.reward_qty)
   on conflict(user_id,item_id) do update set quantity=public.sq_inventory.quantity+excluded.quantity;
end $$;

revoke all on function public.sq_create_trade(uuid,jsonb,jsonb) from public, anon;
revoke all on function public.sq_respond_trade(uuid,boolean) from public, anon;
revoke all on function public.sq_claim_quest(text,text) from public, anon;
grant execute on function public.sq_create_trade(uuid,jsonb,jsonb) to authenticated;
grant execute on function public.sq_respond_trade(uuid,boolean) to authenticated;
grant execute on function public.sq_claim_quest(text,text) to authenticated;

-- Admin-managed quest definitions only. Seed examples; set active=false until progress is
-- written by trusted game-result logic (never accept arbitrary client progress).
insert into public.sq_quests(quest_id,period,title,target,reward_item,reward_qty)
values ('weekly_science','weekly','Weekly Science Explorer',5,'crystal_bundle',1),
       ('monthly_research','monthly','Monthly Researcher',20,'rare_case',1)
on conflict (quest_id,period) do nothing;

-- Admins create/update quest definitions in the SQL editor or a trusted admin backend.
