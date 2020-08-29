<?php

namespace fedyak\YandexCloudIAMToken;

class IAMTokenException extends \Exception
{

    private $error_object;


    public function __construct($error)
    {
        $this->message      = $error->message ?? null;
        $this->code         = $error->code ?? null;
        $this->error_object = $error;
    }


    public function getError()
    {
        return $this->error_object;
    }


}
