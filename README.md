# wechatpay-guzzle-middleware

## 概览

[微信支付API v3](https://wechatpay-api.gitbook.io/wechatpay-api-v3/)的[Guzzle HttpClient](http://docs.guzzlephp.org/)中间件Middleware，实现了请求签名的生成和应答签名的验证。

如果你是使用Guzzle的商户开发者，可以在构造`GuzzleHttp\Client`时将`WechatPayGuzzleMiddleware`传入，得到的`GuzzleHttp\Client`实例在执行请求时将自动携带身份认证信息，并检查应答的微信支付签名。



## 项目状态

当前版本为`0.1.1`测试版本。请商户的专业技术人员在使用时注意系统和软件的正确性和兼容性，以及带来的风险。



## 环境要求

我们开发和测试使用的环境如下：

+ PHP 5.5+ / PHP 7.0+
+ guzzlehttp/guzzle 6.0+



## 安装

可以使用PHP包管理工具composer引入SDK到项目中：

#### Composer

方式一：在项目目录中，通过composer命令行添加：
```shell
composer require wechatpay/wechatpay-guzzle-middleware
```


方式二：在项目的composer.json中加入以下配置：

```json
    "require": {
        "wechatpay/wechatpay-guzzle-middleware": "^0.1.1"
    }
```
添加配置后，执行安装
```shell
composer install
```



## 开始

首先，通过`WechatPayMiddlewareBuilder`构建一个`WechatPayMiddleware`，然后将其加入`GuzzleHttp\Client`的`HandlerStack`中。我们提供相应的方法，可以方便的传入商户私钥和微信支付平台证书等信息。

```php
use WechatPay\GuzzleMiddleware\WechatPayMiddleware;
use WechatPay\GuzzleMiddleware\Util\PemUtil;

// 商户相关配置
$merchantId = '1000100'; // 商户号
$merchantSerialNumber = 'XXXXXXXXXX'; // 商户API证书序列号
$merchantPrivateKey = PemUtil::loadPrivateKey('/path/to/mch/private/key.pem'); // 商户私钥
// 微信支付平台配置
$wechatpayCertificate = PemUtil::loadCertificate('/path/to/wechatpay/cert.pem'); // 微信支付平台证书

// 构造一个WechatPayMiddleware
$wechatpayMiddleware = WechatPayMiddleware::builder()
    ->withMerchant($merchantId, $merchantSerialNumber, $merchantPrivateKey) // 传入商户相关配置
    ->withWechatPay([ $wechatpayCertificate ]) // 可传入多个微信支付平台证书，参数类型为array
    ->build();

// 将WechatPayMiddleware添加到Guzzle的HandlerStack中
$stack = HandlerStack::create();
$stack->push($wechatpayMiddleware, 'wechatpay');

// 创建Guzzle HTTP Client时，将HandlerStack传入
$client = new GuzzleHttp\Client(['handler' => $stack]);


// 接下来，正常使用Guzzle发起API请求，WechatPayMiddleware会自动地处理签名和验签
try {
    $resp = $client->request('GET', 'https://api.mch.weixin.qq.com/v3/...', [
        'headers' => [ 'Accept' => 'application/json' ]
    ]);

    $resp = $client->request('POST', 'https://api.mch.weixin.qq.com/v3/...', [
        'json' => [ // JSON请求体
            'field1' => 'value1',
            'field2' => 'value2'
        ],
        'headers' => [ 'Accept' => 'application/json' ]
    ]);
    
    // 上传图片
    $resp = $client->request('POST', 'https://api.mch.weixin.qq.com/v3/...', [
        'body' =>\GuzzleHttp\Psr7\stream_for("body的内容"),
        'headers' => [ 
               'Accept'       => 'application/json',
               "Content-Type" => " multipart/form-data;boundary=boundary",
                // meta的json串 ,签名使用
               "metaJson"     => '{ "filename": "filea.jpg", "sha256": " hjkahkjsjkfsjk78687dhjahdajhk " }',
            ]
    ]);




} catch (RequestException $e) {
    // 进行错误处理
    echo $e->getMessage()."\n";
    if ($e->hasResponse()) {
        echo $e->getResponse()->getStatusCode().' '.$e->getResponse()->getReasonPhrase()."\n";
        echo $e->getResponse()->getBody();
    }
    return;
}
```



## 定制

当默认的本地签名和验签方式不适合你的系统时，你可以通过实现`Signer`或者`Verifier`来定制签名和验签。比如，你的系统把商户私钥集中存储，业务系统需通过远程调用进行签名，你可以这样做。

```php
use WechatPay\GuzzleMiddleware\Auth\Signer;
use WechatPay\GuzzleMiddleware\Auth\SignatureResult;
use WechatPay\GuzzleMiddleware\Auth\WechatPay2Credentials;

class CustomSigner implements Signer
{
    public function sign($message)
    {
        // 调用签名RPC服务，然后返回包含签名和证书序列号的SignatureResult
        return new SignatureResult('xxxx', 'yyyyy');
    }
}

$credentials = new WechatPay2Credentials($merchantId, new CustomSigner);

$wechatpayMiddleware = WechatPayMiddleware::builder()
    ->withCredentials($credentials)
    ->withWechatPay([ $wechatpayCertificate ])
    ->build();
```



## 常见问题

### 如何下载平台证书？

使用`WechatPayMiddlewareBuilder`需要调用`withWechatpay`设置[微信支付平台证书](https://wechatpay-api.gitbook.io/wechatpay-api-v3/ren-zheng/zheng-shu#ping-tai-zheng-shu)，而平台证书又只能通过调用[获取平台证书接口](https://wechatpay-api.gitbook.io/wechatpay-api-v3/jie-kou-wen-dang/ping-tai-zheng-shu#huo-qu-ping-tai-zheng-shu-lie-biao)下载。为了解开"死循环"，你可以在第一次下载平台证书时，按照下述方法临时"跳过”应答签名的验证。

```php
use WechatPay\GuzzleMiddleware\Validator;

class NoopValidator implements Validator
{
    public function validate(\Psr\Http\Message\ResponseInterface $response)
    {
        return true;
    }
}

$wechatpayMiddleware = WechatPayMiddleware::builder()
    ->withMerchant($merchantId, $merchantSerialNumber, $merchantPrivateKey)
    ->withValidator(new NoopValidator) // NOTE: 设置一个空的应答签名验证器，**不要**用在业务请求
    ->build();
```

**注意**：业务请求请使用标准的初始化流程，务必验证应答签名。

### 证书和回调解密需要的AesGcm解密在哪里？

请参考[AesUtil.php](src/Util/AesUtil.php)。



## 联系我们

如果你发现了**BUG**或者有任何疑问、建议，请通过issue进行反馈。

也欢迎访问我们的[开发者社区](https://developers.weixin.qq.com/community/pay)。