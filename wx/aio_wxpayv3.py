
from aiohttp import ClientSession
from wechatpayv3 import WeChatPay,SignType,WeChatPayType

from .core import AioCore

class AioWxPayV3(WeChatPay):
    def __init__(self,
                 wechatpay_type,
                 mchid,
                 private_key,
                 cert_serial_no,
                 appid,
                 apiv3_key,
                 notify_url=None,
                 cert_dir=None,
                 logger=None,
                 partner_mode=False,
                 session:ClientSession=None):
        """
        :param wechatpay_type: 微信支付类型，示例值:WeChatPayType.MINIPROG
        :param mchid: 直连商户号，示例值:'1230000109'
        :param private_key: 商户证书私钥，示例值:'MIIEvwIBADANBgkqhkiG9w0BAQE...'
        :param cert_serial_no: 商户证书序列号，示例值:'444F4864EA9B34415...'
        :param appid: 应用ID，示例值:'wxd678efh567hg6787'
        :param apiv3_key: 商户APIv3密钥，示例值:'a12d3924fd499edac8a5efc...'
        :param notify_url: 通知地址，示例值:'https://www.weixin.qq.com/wxpay/pay.php'
        :param cert_dir: 平台证书存放目录，示例值:'/server/cert'
        :param logger: 日志记录器，示例值logging.getLoger('demo')
        :param partner_mode: 接入模式，默认False为直连商户模式，True为服务商模式
        :param session: 传入session的话，将节省http请求连接的时间
        """
        self._type = wechatpay_type
        self._mchid = mchid
        self._appid = appid
        self._notify_url = notify_url
        self._core = AioCore(mchid=self._mchid,
                          cert_serial_no=cert_serial_no,
                          private_key=private_key,
                          apiv3_key=apiv3_key,
                          cert_dir=cert_dir,
                          logger=logger,
                          session=session)
        self._partner_mode = partner_mode

        def sign(self, data, sign_type=SignType.RSA_SHA256):
            """使用RSAwithSHA256或HMAC_256算法计算签名值供调起支付时使用
            :param data: 需要签名的参数清单
            :微信支付订单采用RSAwithSHA256算法时，示例值:['wx888','1414561699','5K8264ILTKCH16CQ2502S....','prepay_id=wx201410272009395522657....']
            :微信支付分订单采用HMAC_SHA256算法时，示例值:{'mch_id':'1230000109','service_id':'88888888000011','out_order_no':'1234323JKHDFE1243252'}
            """
            return self._core.sign(data, sign_type)

        async def decrypt_callback(self, headers, body):
            """解密回调接口收到的信息，仅返回resource解密后的参数字符串，此接口为兼容旧版本而保留，建议调用callback()
            :param headers: 回调接口收到的headers
            :param body: 回调接口收到的body
            """
            return self._core.decrypt_callback(headers, body)

        async def callback(self, headers, body):
            """解密回调接口收到的信息，返回所有传入的参数
            :param headers: 回调接口收到的headers
            :param body: 回调接口收到的body
            """
            return await self._core.callback(headers, body)

        def decrypt(self, ciphtext):
            """解密微信支付平台返回的信息中的敏感字段
            :param ciphtext: 加密后的敏感字段，示例值:'Qe41VhP/sGdNeTHMQGlxCWiUyHu6XNO9GCYln2Luv4HhwJzZBfcL12sB+PgZcS5NhePBog30NgJ1xRaK+gbGDKwpg=='
            """
            return self._core.decrypt(ciphtext)