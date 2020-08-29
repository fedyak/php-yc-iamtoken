<?php

namespace fedyak\YandexCloudIAMToken;

use phpseclib\Crypt\RSA;
use Ixudra\Curl\CurlService;

use fedyak\YandexCloudIAMToken\IAMTokenException;

/**
 * @author Fedor Kornilev <fedor.nt82@mail.ru>
 * 
 * IAM-token for a Yandex Cloud service account
 */
class ServiceAccountIAMToken
{

    /**
     * Headers
     *
     * @var array
     */
    private $header = [];


    /**
     * Payload
     *
     * @var array
     */
    private $payload = [];


    /**
     * RSA Private Key
     * @var string
     */
    private $private_key = '';


    /**
     * JWT
     * @var string
     */
    private $jwt;


    /**
     *
     * @param string $service_account_id
     * @param string $key_id
     * @param string $private_key
     */
    public function __construct(string $service_account_id, string $key_id, string $private_key)
    {
        $this->header = [
            'typ' => 'JWT',
            'alg' => 'PS256',
            'kid' => $key_id
        ];

        $now = time();

        $this->payload = [
            'aud' => 'https://iam.api.cloud.yandex.net/iam/v1/tokens',
            'iss' => $service_account_id,
            'iat' => $now,
            'exp' => $now + 3600 //1 hour
        ];

        $this->private_key = $private_key;
    }


    /**
     * Get JSON Web Token
     *
     * @return string
     */
    public function getJWT(): string
    {
        $sign = $this->sign($this->private_key);

        $this->jwt = implode('.', [
            $this->base64urlEncode($this->header),
            $this->base64urlEncode($this->payload),
            $this->base64urlEncode($sign, false)
        ]);

        return $this->jwt;
    }


    /**
     *
     * @throws Exception
     * @return string
     */
    public function getIAMToken(): string
    {
        if (empty($this->jwt)) {
            $this->jwt = $this->getJWT();
        }
        
        $curl = new CurlService();
        
        $response = $curl->to('https://iam.api.cloud.yandex.net/iam/v1/tokens')
               ->withData(['jwt' => $this->jwt])
               ->asJson()
               ->post();
        
        if (!isset($response->iamToken)) {
            throw new IAMTokenException($response);
        }
            
        return $response->iamToken;
    }


    /**
     * base64urlEncode
     *
     * @param mixed $data
     * @param bool $json_encode
     * @return string
     */
    private function base64urlEncode($data, $json_encode = true): string
    {
        $data = $json_encode ? json_encode($data) : $data;

        return str_replace('=', '', strtr(base64_encode($data), '+/', '-_'));
    }


    /**
     * Sign
     *
     * @param string $private_key
     * @return string
     */
    private function sign(string $private_key)
    {
        $signature_base_string = implode('.', [
            $this->base64urlEncode($this->header),
            $this->base64urlEncode($this->payload)
        ]);

        $rsa = new RSA();

        $rsa->loadKey($private_key);

        $rsa->setHash('sha256');
        $rsa->setMGFHash('sha256');
        $rsa->setSignatureMode(RSA::SIGNATURE_PSS);

        return $rsa->sign($signature_base_string);
    }

}
