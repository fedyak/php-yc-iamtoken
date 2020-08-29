# IAM-token for a Yandex Cloud service account

Getting an IAM token for a Yandex Cloud service account

## Install

`composer require fedyak/php-yc-iamtoken`

## Example

```php

// Service Account ID
$service_account_id = '....';

// Service Account Key ID
$key_id             = '....';

$rsa_private_key = file_get_contents('private.pem');

$iam = new ServiceAccountIAMToken($service_account_id, $key_id, $rsa_private_key);

//$jwt = $iam->getJWT();        //JSON Web Token

$iam_token = $iam->getIAMToken();

```