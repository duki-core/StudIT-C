# PoC: устойчивость и утечки (PostgreSQL 16 + fakeredis): сбой Redis после коммита, Redis как единая точка отказа, исчерпание пула БД, утечка объёма операций через transaction_id.
import os, asyncio, time
os.environ['POSTGRES_DSN']='postgresql://postgres@localhost:5432/bank'
os.environ['REDIS_URL']='redis://x'
import app.security as s, app.schemas as sc
s.user_id=s.get_current_user_id; sc.TransferIn=sc.TransferRequest; sc.TxOut=sc.TransactionOut
import fakeredis.aioredis as fr, app.redis_client as rc
class DownRedis:
    async def get(self,*a,**k): raise ConnectionError("Redis unavailable")
    async def delete(self,*a,**k): raise ConnectionError("Redis unavailable")
from app.main import app
from app.db import init_db, get_pool
import app.db as dbm
import httpx, asyncpg
async def main():
    await init_db(); pool=await get_pool()
    bal=lambda: pool.fetch('select id,balance_cents from accounts order by id')
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, raise_app_exceptions=False), base_url='http://t') as c:
        T=lambda: c.post('/transfer',headers={'X-User-Id':'1'},json={'from_account_id':1,'to_account_id':2,'amount_cents':1000})
        # 1,2: Redis down
        rc._client=DownRedis()
        print('1) before', [tuple(r) for r in await bal()])
        r=await T(); print('1) transfer with Redis down ->', r.status_code, r.text[:40])
        print('1) after 1st', [tuple(r) for r in await bal()])
        r=await T(); print('1) client retries ->', r.status_code)
        print('1) after retry', [tuple(r) for r in await bal()], 'tx count', await pool.fetchval('select count(*) from transactions'))
        r=await c.get('/transactions',headers={'X-User-Id':'1'}); print('2) history with Redis down ->', r.status_code)
        rc._client=fr.FakeRedis(decode_responses=True)
        # 8: global ids
        a=(await c.post('/transfer',headers={'X-User-Id':'1'},json={'from_account_id':1,'to_account_id':2,'amount_cents':1})).json()['transaction_id']
        for _ in range(7): await c.post('/transfer',headers={'X-User-Id':'2'},json={'from_account_id':2,'to_account_id':1,'amount_cents':1})
        b=(await c.post('/transfer',headers={'X-User-Id':'1'},json={'from_account_id':1,'to_account_id':2,'amount_cents':1})).json()['transaction_id']
        print(f'8) user1 tx ids {a} -> {b}: между ними {b-a-1} чужих операций (реально было 7)')
        # 3: pool exhaustion
        await pool.execute("insert into transactions(from_account_id,to_account_id,amount_cents) select 1,2,1 from generate_series(1,3000000)")
        await pool.execute("analyze")
        t=time.time(); r=await T(); base=time.time()-t; print(f'3) transfer latency idle: {base*1000:.0f} ms', r.status_code)
        t=time.time(); r=await c.get('/transactions',headers={'X-User-Id':'1'},params={'search':'zz'}); one=time.time()-t; print(f'3) one search: {one:.2f} s', r.status_code)
        async def timed_transfer():
            await asyncio.sleep(0.3); t=time.time(); r=await T(); return time.time()-t, r.status_code
        res=await asyncio.gather(*[c.get('/transactions',headers={'X-User-Id':'1'},params={'search':'zz'}) for _ in range(10)], timed_transfer())
        print(f'3) transfer latency while 10 searches run: {res[-1][0]:.2f} s', res[-1][1])
asyncio.run(main())
