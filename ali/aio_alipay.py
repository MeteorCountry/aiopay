
from alipay import BaseAliPay
import aiohttp

# PKCS1,非java 2048
class AioAliPay(BaseAliPay):
    '''
    修改 verified_sync_response 方法，使 alipay 包适用于 async/await 代码
    '''

    def __init__(self,*args,session:aiohttp.ClientSession=None,**kwargs):
        '''
        :param args:
        :param session: 传入session的话，将节省http请求连接的时间
        :param kwargs:
        '''
        super().__init__(*args,**kwargs)
        self.session = session

    async def verified_sync_response(self, data, response_type):
        url = self._gateway + "?" + self.sign_data(data)
        if self.session:
            async with self.session.request('GET',url) as res:
                raw_string = await res.text()
                return self._verify_and_return_sync_response(raw_string, response_type)
        async with aiohttp.request('GET',url) as res:
            raw_string = await res.text()
            return self._verify_and_return_sync_response(raw_string, response_type)

if __name__ == '__main__':
    pass