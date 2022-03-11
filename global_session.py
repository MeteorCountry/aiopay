
import asyncio
import aiohttp

class GlobalSession:
    def __init__(self):
        self._session:aiohttp.ClientSession = None
        self._t_conn:aiohttp.TCPConnector = None

    @property
    def t_conn(self)->aiohttp.TCPConnector:
        if not self._t_conn:
            self._t_conn = aiohttp.TCPConnector(limit=400)
        return self._t_conn

    @property
    def session(self)->aiohttp.ClientSession:
        if not self._session:
            self._session = aiohttp.ClientSession(connector=self.t_conn)
        return self._session

    async def close(self):
        if self._t_conn:
            await self._t_conn.close()

if __name__ == '__main__':
    g_session = GlobalSession()
    async def test():
        async with g_session.session.get(url='https://www.baidu.com/') as res:
            print(res.status)
        await g_session.close()
        # await g_session.close()
    asyncio.run(test())
