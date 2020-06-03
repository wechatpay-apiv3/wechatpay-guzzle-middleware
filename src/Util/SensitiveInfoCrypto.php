<?php
/**
 * SensitiveInfoCrypto
 * PHP version 7
 *
 * @category Class
 * @package  WechatPay
 * @author   WeChatPay Team
 * @link     https://pay.weixin.qq.com
 */
namespace WechatPay\GuzzleMiddleware\Util;

/**
 * Encrypt/Decrypt the sensitive information by the certificates pair.
 *
 * <code>
 * // Encrypt usage:
 * $codec = new SensitiveInfoCrypto(PemUtil::loadCertificate('/downloaded/pubcert.pem'));
 * $json = json_encode(['name' => $codec('Alice')]);
 * // That's simple!
 *
 * // Decrypt usage:
 * $codec = new SensitiveInfoCrypto(null, PemUtil::loadPrivateKey('/merchant/key.pem'));
 * $decrypted = $codec->setStage('decrypt')('base64 encoding message was given by the payment plat');
 * // That's simple too!
 *
 * // Working both Encrypt and Decrypt usages:
 * $codec = new SensitiveInfoCrypto(
 *     PemUtil::loadCertificate('/merchant/cert.pem'),
 *     PemUtil::loadPrivateKey('/merchant/key.pem')
 * );
 * $encrypted = $codec('Carol');
 * $decrypted = $codec->setStage('decrypt')($encrypted);
 * // Having fun with this!
 * </code>
 *
 * @package  WechatPay
 */
class SensitiveInfoCrypto implements \JsonSerializable {

    /**
     * @var int Equal to OPENSSL_PKCS1_OAEP_PADDING constant,
     *          to prevent the fault error while the PHP_VERSION < 7.0.
     */
    const OPENSSL_PKCS1_OAEP_PADDING = 4;

    /**
     * @var resource|null $publicCert The offical public certificate,
     *                                which should be downloaded via `/v3/certificates`
     */
    private $publicCert;

    /**
     * @var resource|null $privateCert The merchant private certificate
     */
    private $privateCert;

    /**
     * @var string $message The encryped or decrypted content
     */
    private $message;

    /**
     * @var string $stage The codec working scenario, default is `encrypt`.
     *                    Mention here: while toggle the scenario,
     *                    the next stage is the previous one.
     */
    private $stage = 'encrypt';

    /**
     * @var array $scenarios Methods that allowed.
     */
    private static $scenarios = ['encrypt', 'decrypt'];

    /**
     * Constructor
     *
     * @param resource|null $publicCert The offical public certificate resource
     * @param resource|null $privateCert The merchant private certificate resource
     */
    public function __construct($publicCert, $privateCert = null) {
        $this->publicCert = $publicCert;
        $this->privateCert = $privateCert;
    }

    /**
     * Encrypt the string by the public certificate
     *
     * @param string $str The content shall be encrypted
     *
     * @return SensitiveInfoCrypto
     */
    private function encrypt($str) {
        openssl_public_encrypt($str, $encrypted, $this->publicCert, self::OPENSSL_PKCS1_OAEP_PADDING);
        $this->message = base64_encode($encrypted);

        return $this;
    }

    /**
     * Decrypt the string by the private certificate
     *
     * @param string $str The content shall be decrypted
     *
     * @return SensitiveInfoCrypto
     */
    private function decrypt($str) {
        openssl_private_decrypt(base64_decode($str), $decrypted, $this->privateCert, self::OPENSSL_PKCS1_OAEP_PADDING);
        $this->message = $decrypted;

        return $this;
    }

    /**
     * Specify data which should be
     *
     * @return string
     */
    public function jsonSerialize() {
        return $this->message;
    }

    /**
     * Toggle the codec instance onto `encrypt` or `decrypt` stage
     *
     * @param string $scenario Should be `encrypt` or `decrypt`
     *
     * @throws \InvalidArgumentException if the scenario is invalid.
     *
     * @return SensitiveInfoCrypto
     */
    public function setStage($scenario) {
        if (!in_array($scenario, self::$scenarios)) {
            throw new \InvalidArgumentException(sprintf(
                'Cannot setStage `%s`, here is only allowed one of the %s',
                $scenario,
                \implode(', ', self::$scenarios)
            ));
        }
        $this->stage = $scenario;

        return $this;
    }

    public function __invoke($str) {
        return (clone $this)->{$this->stage}($str);
    }

    public function __toString() {
        return $this->jsonSerialize();
    }
}
