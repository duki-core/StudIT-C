# PoC-проверка логических находок на запущенном сервисе (PostgreSQL 16 + fakeredis): deadlock, перевод самому себе, кеш, ошибки 500, перебор счетов.
# Исходный код сервиса не меняется: имена user_id/TransferIn/TxOut подставляются только здесь, т.к. в main.py они импортируются под неверными именами.
import os, asyncio
os.environ['POSTGRES_DSN']='postgresql://postgres@localhost:5432/bank'
os.environ['REDIS_URL']='redis://x'
import app.security as s, app.schemas as sc
s.user_id=s.get_current_user_id; sc.TransferIn=sc.TransferRequest; sc.TxOut=sc.TransactionOut
import fakeredis.aioredis as fr, app.redis_client as rc
R=fr.FakeRedis(decode_responses=True); rc._client=R
from app.main import app
from app.db import init_db, get_pool
import httpx
async def main():
    await init_db(); pool=await get_pool()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, raise_app_exceptions=False), base_url='http://t') as c:
        T=lambda uid,f,t,a: c.post('/transfer',headers={'X-User-Id':str(uid)},json={'from_account_id':f,'to_account_id':t,'amount_cents':a})
        print('accounts', [tuple(r) for r in await pool.fetch('select * from accounts order by id')])
        # 1 deadlock: A->B by user1 and B->A by user2, 40 parallel
        for run in range(3):
            rs=await asyncio.gather(*[T(1,1,2,1) if i%2==0 else T(2,2,1,1) for i in range(40)])
            from collections import Counter; print('1) deadlock run',run, Counter(x.status_code for x in rs))
        # 2 self-transfer
        r=await T(1,1,1,100); print('2) self', r.status_code, r.text)
        # 3 cache
        await R.set('tx:1:20:','x'); r=await c.get('/transactions',headers={'X-User-Id':'1'}); print('3) cache hit ->', r.status_code, r.text)
        await R.delete('tx:1:20:'); r=await c.get('/transactions',headers={'X-User-Id':'1'}); print('3) no cache -> items', len(r.json()))
        await R.set('tx:1:20:','x'); await T(1,1,2,1); print('3) key after transfer still exists:', await R.exists('tx:1:20:')); await R.delete('tx:1:20:')
        print('3) keys ever written by service:', await R.keys('*'))
        # 4 errors
        r=await T(1,2**63,2,1); print('4) from=2^63', r.status_code, r.text[:80])
        r=await c.get('/transactions',headers={'X-User-Id':str(2**63)}); print('4) uid=2^63 GET', r.status_code, r.text[:80])
        r=await T(2**63,1,2,1); print('4) uid=2^63 POST', r.status_code, r.text[:80])
        r=await c.get('/transactions',headers={'X-User-Id':'-5'}); print('4) uid=-5', r.status_code, r.text[:60])
        r=await c.get('/transactions',headers={'X-User-Id':' 1_0 '}); print("4) uid=' 1_0 '", r.status_code, r.text[:60], int(' 1_0 '))
        r=await T(1,1,2,2**63); print('4) amount=2^63', r.status_code, r.text[:60])
        # 5 oracle
        r=await T(1,1,999,1); print('5) to=999', r.status_code, r.text)
        r=await T(1,1,2,1); print('5) to=2', r.status_code, r.text)
        r=await T(1,999,2,1); print('5) from=999 (nonexistent)', r.status_code, r.text)
        r=await T(1,2,1,1); print('5) from=2 (foreign)', r.status_code, r.text)
        print('balances', [tuple(r) for r in await pool.fetch('select * from accounts order by id')])
asyncio.run(main())
