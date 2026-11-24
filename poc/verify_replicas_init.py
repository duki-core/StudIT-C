# PoC: гонка init_db при одновременном старте нескольких реплик (задвоение тестовых счетов, падение при CREATE TABLE).
import asyncio, asyncpg, os
async def run(i):
    DSN=f'postgresql://postgres@localhost:5432/seed{i}'
    c=await asyncpg.connect('postgresql://postgres@localhost:5432/postgres')
    await c.execute(f'drop database if exists seed{i}'); await c.execute(f'create database seed{i}'); await c.close()
    async def one():
        ns={'os':os}; os.environ['POSTGRES_DSN']=DSN
        exec(compile(open('app/db.py').read(),'db.py','exec'),ns); return await ns['init_db']()
    res=await asyncio.gather(*[one() for _ in range(4)], return_exceptions=True)
    c=await asyncpg.connect(DSN); n=await c.fetchval('select count(*) from accounts'); await c.close()
    errs=[type(e).__name__ for e in res if isinstance(e,Exception)]
    return n, errs
async def main():
    from collections import Counter
    out=[await run(i) for i in range(10)]
    print('6) accounts per run:', [o[0] for o in out]); print('   errors:', Counter(e for o in out for e in o[1]))
asyncio.run(main())
